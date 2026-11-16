"""SupportDesk milestone 1: same-origin UI and authenticated ticket API."""
import hashlib
import hmac
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Literal

from fastapi import Cookie, Depends, FastAPI, HTTPException, Query, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

DB_PATH = os.environ.get('SUPPORTDESK_DB', 'supportdesk.db')
SECURE_COOKIE = os.environ.get('COOKIE_SECURE', 'false').lower() == 'true'
STATIC = Path(__file__).parent / 'static'
app = FastAPI(title='SupportDesk', version='0.1.0')

@contextmanager
def db():
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute('PRAGMA foreign_keys=ON')
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()

def init_db():
    with db() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL,
          name TEXT NOT NULL, password TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('customer','agent','admin')));
        CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS tickets(id INTEGER PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL,
          priority TEXT NOT NULL CHECK(priority IN ('low','medium','high')), status TEXT NOT NULL DEFAULT 'open'
          CHECK(status IN ('open','in_progress','resolved')), customer_id INTEGER NOT NULL REFERENCES users(id),
          assignee_id INTEGER REFERENCES users(id), created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY, ticket_id INTEGER NOT NULL REFERENCES tickets(id),
          author_id INTEGER NOT NULL REFERENCES users(id), body TEXT NOT NULL, created_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, ticket_id INTEGER NOT NULL REFERENCES tickets(id),
          actor_id INTEGER NOT NULL REFERENCES users(id), action TEXT NOT NULL, created_at INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS ticket_customer ON tickets(customer_id);
        CREATE INDEX IF NOT EXISTS ticket_assignee ON tickets(assignee_id);
        CREATE TABLE IF NOT EXISTS login_attempts(email TEXT PRIMARY KEY, failures INTEGER NOT NULL, reset_at INTEGER NOT NULL);
        ''')

def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()
    return salt + ':' + digest

def check_password(password, stored):
    return hmac.compare_digest(hash_password(password, stored.split(':')[0]), stored)

def current_user(session: str | None = Cookie(default=None)):
    if not session:
        raise HTTPException(401, 'Please sign in')
    with db() as c:
        user = c.execute('SELECT u.id,u.name,u.email,u.role FROM users u JOIN sessions s ON u.id=s.user_id WHERE s.token=? AND s.expires>?',
                         (hashlib.sha256(session.encode()).hexdigest(), int(time.time()))).fetchone()
    if user is None:
        raise HTTPException(401, 'Session expired; please sign in')
    return dict(user)

class Credentials(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=256)

class NewTicket(BaseModel):
    title: str = Field(min_length=3, max_length=160, pattern=r'\S')
    description: str = Field(min_length=5, max_length=10000, pattern=r'\S')
    priority: Literal['low','medium','high'] = 'medium'

class UpdateTicket(BaseModel):
    status: Literal['open','in_progress','resolved']

class Assignment(BaseModel):
    assignee_id: int | None

class Comment(BaseModel):
    body: str = Field(min_length=1, max_length=5000, pattern=r'\S')

def ticket_for(c, ticket_id, user, write=False):
    t = c.execute('SELECT * FROM tickets WHERE id=?', (ticket_id,)).fetchone()
    if t is None or (user['role']=='customer' and t['customer_id']!=user['id']):
        raise HTTPException(404, 'Ticket not found')
    if write and user['role']=='agent' and t['assignee_id']!=user['id']:
        raise HTTPException(403, 'Only the assigned agent or an administrator can change this ticket')
    return dict(t)

def audit(c, ticket_id, user_id, action):
    c.execute('INSERT INTO audit(ticket_id,actor_id,action,created_at) VALUES (?,?,?,?)',
              (ticket_id,user_id,action,int(time.time())))

@app.middleware('http')
async def security_headers(request, call_next):
    # JSON-only API writes plus same-origin fetch metadata protect cookie authentication.
    if request.method in ('POST','PATCH','DELETE'):
        if request.headers.get('sec-fetch-site') == 'cross-site':
            return Response('Cross-site write denied', status_code=403)
        if request.headers.get('content-type','').split(';')[0] != 'application/json':
            return Response('JSON required', status_code=415)
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    response.headers['Cache-Control'] = 'no-store'
    return response

@app.post('/api/login')
def login(data: Credentials, response: Response):
    email, now = data.email.strip().lower(), int(time.time())
    with db() as c:
        attempt = c.execute('SELECT * FROM login_attempts WHERE email=?',(email,)).fetchone()
        if attempt and attempt['reset_at']>now and attempt['failures']>=5:
            raise HTTPException(429, 'Too many attempts. Try again in 15 minutes.')
        u = c.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
        valid = check_password(data.password, u['password']) if u else check_password(data.password, hash_password('unused-password'))
        if not u or not valid:
            count = attempt['failures']+1 if attempt and attempt['reset_at']>now else 1
            reset = attempt['reset_at'] if attempt and attempt['reset_at']>now else now+900
            c.execute('INSERT OR REPLACE INTO login_attempts VALUES (?,?,?)',(email,count,reset))
            c.commit()  # Persist failure before raising the HTTP exception.
            raise HTTPException(401, 'Invalid email or password')
        c.execute('DELETE FROM login_attempts WHERE email=?',(email,))
        c.execute('DELETE FROM sessions WHERE expires<=?',(now,))
        token = secrets.token_urlsafe(32)
        c.execute('INSERT INTO sessions VALUES (?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),u['id'],now+28800))
    response.set_cookie('session',token,httponly=True,samesite='strict',secure=SECURE_COOKIE,max_age=28800)
    return {'id':u['id'],'name':u['name'],'role':u['role']}

@app.post('/api/logout')
def logout(response: Response, session: str | None = Cookie(default=None)):
    with db() as c:
        if session:
            c.execute('DELETE FROM sessions WHERE token=?',(hashlib.sha256(session.encode()).hexdigest(),))
    response.delete_cookie('session')
    return {'ok':True}

@app.get('/api/me')
def me(user=Depends(current_user)):
    return user

@app.get('/api/agents')
def agents(user=Depends(current_user)):
    if user['role']!='admin':
        raise HTTPException(403,'Administrator access required')
    with db() as c:
        return [dict(r) for r in c.execute("SELECT id,name FROM users WHERE role='agent'")]

@app.get('/api/tickets')
def tickets(q: str = Query('',max_length=100), status: Literal['open','in_progress','resolved'] | None = None,
            offset: int = Query(0,ge=0), limit: int = Query(30,ge=1,le=100), user=Depends(current_user)):
    clauses, args = ['1=1'], []
    if user['role']=='customer':
        clauses.append('customer_id=?'); args.append(user['id'])
    if status:
        clauses.append('status=?'); args.append(status)
    if q:
        clauses.append('(instr(lower(title),lower(?))>0 OR instr(lower(description),lower(?))>0)'); args += [q,q]
    where = ' AND '.join(clauses)
    with db() as c:
        total = c.execute('SELECT count(*) FROM tickets WHERE '+where,args).fetchone()[0]
        rows = c.execute('SELECT * FROM tickets WHERE '+where+' ORDER BY updated_at DESC,id DESC LIMIT ? OFFSET ?',args+[limit,offset])
        return {'items':[dict(r) for r in rows], 'total':total}

@app.post('/api/tickets',status_code=201)
def create_ticket(data: NewTicket,user=Depends(current_user)):
    now = int(time.time())
    with db() as c:
        cursor = c.execute('INSERT INTO tickets(title,description,priority,customer_id,created_at,updated_at) VALUES (?,?,?,?,?,?)',
                           (data.title.strip(),data.description.strip(),data.priority,user['id'],now,now))
        ticket_id = cursor.lastrowid
        audit(c,ticket_id,user['id'],'Ticket created')
        return ticket_for(c,ticket_id,user)

@app.get('/api/tickets/{ticket_id}')
def detail(ticket_id:int,user=Depends(current_user)):
    with db() as c:
        t=ticket_for(c,ticket_id,user)
        for table in ('comments','audit'):
            t[table]=[dict(r) for r in c.execute('SELECT * FROM '+table+' WHERE ticket_id=? ORDER BY id',(ticket_id,))]
        return t

@app.patch('/api/tickets/{ticket_id}/status')
def change_status(ticket_id:int,data:UpdateTicket,user=Depends(current_user)):
    with db() as c:
        t=ticket_for(c,ticket_id,user,write=True)
        if user['role']=='customer':
            raise HTTPException(403,'Agents manage ticket status')
        allowed={'open':{'in_progress'},'in_progress':{'resolved','open'},'resolved':{'open'}}
        if data.status not in allowed[t['status']]:
            raise HTTPException(409,'Invalid status transition')
        c.execute('UPDATE tickets SET status=?,updated_at=? WHERE id=?',(data.status,int(time.time()),ticket_id))
        audit(c,ticket_id,user['id'],f"Status: {t['status']} → {data.status}")
        return ticket_for(c,ticket_id,user)

@app.patch('/api/tickets/{ticket_id}/assignment')
def assign(ticket_id:int,data:Assignment,user=Depends(current_user)):
    if user['role']!='admin':
        raise HTTPException(403,'Administrator access required')
    with db() as c:
        ticket_for(c,ticket_id,user)
        if data.assignee_id is not None and not c.execute("SELECT id FROM users WHERE id=? AND role='agent'",(data.assignee_id,)).fetchone():
            raise HTTPException(422,'Assignee must be an agent')
        c.execute('UPDATE tickets SET assignee_id=?,updated_at=? WHERE id=?',(data.assignee_id,int(time.time()),ticket_id))
        audit(c,ticket_id,user['id'],f'Assigned agent: {data.assignee_id}')
        return ticket_for(c,ticket_id,user)

@app.post('/api/tickets/{ticket_id}/comments',status_code=201)
def comment(ticket_id:int,data:Comment,user=Depends(current_user)):
    with db() as c:
        ticket_for(c,ticket_id,user,write=True)
        c.execute('INSERT INTO comments(ticket_id,author_id,body,created_at) VALUES (?,?,?,?)',(ticket_id,user['id'],data.body.strip(),int(time.time())))
        c.execute('UPDATE tickets SET updated_at=? WHERE id=?',(int(time.time()),ticket_id))
        audit(c,ticket_id,user['id'],'Comment added')
    return {'ok':True}

@app.get('/health')
def health():
    with db() as c:
        c.execute('SELECT 1 FROM users LIMIT 1')
    return {'status':'ok'}

@app.get('/')
def index():
    return FileResponse(STATIC/'index.html')

app.mount('/static',StaticFiles(directory=STATIC),name='static')
