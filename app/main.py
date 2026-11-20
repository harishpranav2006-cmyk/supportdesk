"""SupportDesk authenticated support workspace."""
import hashlib
import hmac
import os
import secrets
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Literal
from fastapi import Cookie, Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import select, insert, update, delete, func, or_, case
from .database import (engine_for, metadata, users, sessions, tickets as ticket_table,
                       comments, audit_events, login_attempts, signup_attempts, employee_profiles, employee_managers, employee_events)

DB_PATH=os.environ.get('SUPPORTDESK_DB',os.environ.get('ASSISTFLOW_DB','supportdesk.db'))
DATABASE_URL=os.environ.get('DATABASE_URL')
SECURE_COOKIE=os.environ.get('COOKIE_SECURE','false').lower()=='true'
STATIC=Path(__file__).parent/'static'
app=FastAPI(title='SupportDesk',version='0.2.0')
SLA_HOURS={'high':24,'medium':72,'low':120}

def engine():
    if os.environ.get('VERCEL') and not DATABASE_URL: raise RuntimeError('DATABASE_URL is required on Vercel')
    return engine_for(DATABASE_URL or 'sqlite:///'+str(Path(DB_PATH).resolve()))
@contextmanager
def db():
    with engine().begin() as connection: yield connection

def init_db():
    from .migrate import migrate
    migrate(engine())

def hash_password(password,salt=None):
    salt=salt or secrets.token_hex(16)
    return salt+':'+hashlib.scrypt(password.encode(),salt=bytes.fromhex(salt),n=16384,r=8,p=1).hex()

def check_password(password,stored):
    return hmac.compare_digest(hash_password(password,stored.split(':')[0]),stored)

DUMMY_HASH=hash_password('unused-password')

def user_context(c,user):
    result={k:user[k] for k in ('id','name','email','role')}
    profile=c.execute(select(employee_profiles).where(employee_profiles.c.user_id==user['id'])).mappings().first()
    if profile:
        result.update({
            'designation':profile['designation'],
            'department':profile['department'],
            'is_active':bool(profile['is_active']),
        })
    else:
        result.update({'designation':None,'department':None,'is_active':True})
    manager_id=c.execute(select(employee_managers.c.user_id).where(employee_managers.c.singleton_id==1)).scalar_one_or_none()
    result['can_manage_employees']=(manager_id==user['id'])
    return result

def require_employee_manager(user):
    if not user.get('can_manage_employees'):
        raise HTTPException(403,'Employee Manager access required')

def current_user(session:str|None=Cookie(default=None)):
    if not session: raise HTTPException(401,'Please sign in')
    with db() as c:
        user=c.execute(
            select(users).join(sessions,users.c.id==sessions.c.user_id).where(
                sessions.c.token==hashlib.sha256(session.encode()).hexdigest(),
                sessions.c.expires>int(time.time())
            )
        ).mappings().first()
        if not user: raise HTTPException(401,'Session expired; please sign in')
        context=user_context(c,user)
        if user['role'] in ('agent','admin') and not context['is_active']:
            raise HTTPException(403,'This employee account is inactive. Contact your Employee Manager.')
        return context

class Credentials(BaseModel):
    email:str=Field(min_length=3,max_length=254)
    password:str=Field(min_length=1,max_length=256)
class Registration(BaseModel):
    name:str=Field(min_length=2,max_length=100)
    email:str=Field(min_length=5,max_length=254,pattern=r'^[^@ ]+@[^@ ]+[.][^@ ]+$')
    password:str=Field(min_length=12,max_length=256)
class NewEmployee(BaseModel):
    name:str=Field(min_length=2,max_length=100)
    email:str=Field(min_length=5,max_length=254)
    password:str=Field(min_length=12,max_length=256)
    role:Literal['agent','admin']
    designation:str=Field(min_length=2,max_length=100)
    department:str|None=Field(None,max_length=100)

class UpdateEmployee(BaseModel):
    name:str|None=Field(None,min_length=2,max_length=100)
    role:Literal['agent','admin']|None=None
    designation:str|None=Field(None,min_length=2,max_length=100)
    department:str|None=Field(None,max_length=100)
    is_active:bool|None=None

class TransferEmployeeManager(BaseModel):
    user_id:int=Field(gt=0)

class NewTicket(BaseModel):
    title:str=Field(min_length=3,max_length=160,pattern=r'\S')
    description:str=Field(min_length=5,max_length=10000,pattern=r'\S')
    priority:Literal['low','medium','high']='medium'
    category:Literal['general','technical','billing','account']='general'

class UpdateTicket(BaseModel):
    status:Literal['open','in_progress','resolved']
    version:int|None=Field(None,ge=1)
class Assignment(BaseModel):
    assignee_id:int|None
    version:int|None=Field(None,ge=1)
class Comment(BaseModel):
    body:str=Field(min_length=1,max_length=5000,pattern=r'\S')
class PasswordChange(BaseModel):
    current_password:str=Field(min_length=1,max_length=256)
    new_password:str=Field(min_length=12,max_length=256)

def scope(user):
    return ticket_table.c.customer_id==user['id'] if user['role']=='customer' else True

def ticket_for(c,ticket_id,user,write=False):
    t=c.execute(select(ticket_table).where(ticket_table.c.id==ticket_id,scope(user))).mappings().first()
    if t is None: raise HTTPException(404,'Ticket not found')
    if write and user['role']=='agent' and t['assignee_id']!=user['id']:
        raise HTTPException(403,'Only the assigned agent or an administrator can change this ticket')
    return dict(t)

def audit(c,ticket_id,user_id,action):
    c.execute(insert(audit_events).values(ticket_id=ticket_id,actor_id=user_id,action=action,created_at=int(time.time())))

def mutate(c,t,data,values):
    expected=data.version if data.version is not None else t['version']
    result=c.execute(update(ticket_table).where(ticket_table.c.id==t['id'],ticket_table.c.version==expected).values(**values,version=ticket_table.c.version+1,updated_at=int(time.time())))
    if result.rowcount!=1: raise HTTPException(409,'This ticket changed. Refresh it and try again.')

@app.middleware('http')
async def security_headers(request,call_next):
    if request.method in ('POST','PATCH','DELETE'):
        if request.headers.get('sec-fetch-site')=='cross-site': return Response('Cross-site write denied',status_code=403)
        if request.headers.get('content-type','').split(';')[0]!='application/json': return Response('JSON required',status_code=415)
    response=await call_next(request)
    response.headers.update({'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",'Cache-Control':'no-store'})
    return response

@app.post('/api/login')
def login(data:Credentials,response:Response):
    email,now=data.email.strip().lower(),int(time.time())
    invalid=False
    with db() as c:
        attempt=c.execute(select(login_attempts).where(login_attempts.c.email==email)).mappings().first()
        if attempt and attempt['reset_at']>now and attempt['failures']>=5: raise HTTPException(429,'Too many attempts. Try again in 15 minutes.')
        u=c.execute(select(users).where(users.c.email==email)).mappings().first()
        valid=check_password(data.password,u['password'] if u else DUMMY_HASH)
        if not u or not valid:
            invalid=True
        elif u['role'] in ('agent','admin'):
            profile=c.execute(
                select(employee_profiles.c.is_active).where(employee_profiles.c.user_id==u['id'])
            ).scalar_one_or_none()
            if profile is None or not profile:
                invalid=True
        if invalid:
            count=attempt['failures']+1 if attempt and attempt['reset_at']>now else 1
            reset=attempt['reset_at'] if attempt and attempt['reset_at']>now else now+900
            if attempt: c.execute(update(login_attempts).where(login_attempts.c.email==email).values(failures=count,reset_at=reset))
            else: c.execute(insert(login_attempts).values(email=email,failures=count,reset_at=reset))
        else:
            c.execute(delete(login_attempts).where(login_attempts.c.email==email))
            c.execute(delete(sessions).where(sessions.c.expires<=now))
            token=secrets.token_urlsafe(32)
            c.execute(insert(sessions).values(token=hashlib.sha256(token.encode()).hexdigest(),user_id=u['id'],expires=now+28800))
    if invalid: raise HTTPException(401,'Invalid email or password or inactive account')
    response.set_cookie('session',token,httponly=True,samesite='strict',secure=SECURE_COOKIE,max_age=28800)
    with db() as c:
        return user_context(c,u)

@app.post('/api/register',status_code=201)
def register(data:Registration,request:Request,response:Response):
    """Create a customer account. Public registration never grants staff roles."""
    email=data.email.strip().lower()
    name=data.name.strip()
    if len(name)<2:
        raise HTTPException(422,'Enter a name with at least two characters.')

    client_ip=(request.client.host if request.client else None) or 'unknown'
    now=int(time.time())
    token=secrets.token_urlsafe(32)
    duplicate=False

    try:
        with db() as c:
            attempt=c.execute(
                select(signup_attempts).where(signup_attempts.c.ip==client_ip)
            ).mappings().first()
            if attempt and attempt['reset_at']>now and attempt['attempts']>=5:
                raise HTTPException(429,'Too many sign-up attempts. Try again in one hour.')

            count=attempt['attempts']+1 if attempt and attempt['reset_at']>now else 1
            reset=attempt['reset_at'] if attempt and attempt['reset_at']>now else now+3600
            if attempt:
                c.execute(
                    update(signup_attempts).where(signup_attempts.c.ip==client_ip)
                    .values(attempts=count,reset_at=reset)
                )
            else:
                c.execute(
                    insert(signup_attempts).values(ip=client_ip,attempts=count,reset_at=reset)
                )
            c.execute(delete(signup_attempts).where(signup_attempts.c.reset_at<=now))

            existing=c.execute(
                select(users.c.id).where(users.c.email==email)
            ).scalar_one_or_none()
            if existing is not None:
                duplicate=True
            else:
                user_id=c.execute(
                    insert(users).values(
                        email=email,
                        name=name,
                        password=hash_password(data.password),
                        role='customer',
                    ).returning(users.c.id)
                ).scalar_one()
                c.execute(insert(sessions).values(
                    token=hashlib.sha256(token.encode()).hexdigest(),
                    user_id=user_id,
                    expires=now+28800,
                ))
    except HTTPException:
        raise
    except Exception as exc:
        from sqlalchemy.exc import IntegrityError
        if isinstance(exc,IntegrityError):
            raise HTTPException(409,'An account with this email already exists. Sign in instead.')
        raise

    if duplicate:
        raise HTTPException(409,'An account with this email already exists. Sign in instead.')

    response.set_cookie(
        'session',token,httponly=True,samesite='strict',secure=SECURE_COOKIE,max_age=28800
    )
    return {'id':user_id,'name':name,'email':email,'role':'customer'}

@app.get('/api/employees')
def employees(user=Depends(current_user)):
    require_employee_manager(user)
    with db() as c:
        rows=c.execute(
            select(
                users.c.id,users.c.name,users.c.email,users.c.role,
                employee_profiles.c.designation,employee_profiles.c.department,
                employee_profiles.c.is_active,employee_profiles.c.created_at,
                employee_managers.c.user_id.label('is_manager'),
            )
            .join(employee_profiles,employee_profiles.c.user_id==users.c.id)
            .outerjoin(employee_managers,employee_managers.c.user_id==users.c.id)
            .where(users.c.role.in_(('agent','admin')))
            .order_by(users.c.role,users.c.name)
        ).mappings().all()
        return [
            {**dict(row),'is_active':bool(row['is_active']),'is_manager':row['is_manager']==row['id']}
            for row in rows
        ]

@app.post('/api/employees',status_code=201)
def create_employee(data:NewEmployee,user=Depends(current_user)):
    require_employee_manager(user)
    email=data.email.strip().lower()
    name=data.name.strip()
    designation=data.designation.strip()
    department=data.department.strip() if data.department else None
    if len(name)<2 or len(designation)<2:
        raise HTTPException(422,'Name and designation must contain at least two characters.')
    if email.count('@')!=1 or '.' not in email.rsplit('@',1)[1] or any(ch.isspace() for ch in email):
        raise HTTPException(422,'Enter a valid employee email address.')
    now=int(time.time())
    try:
        with db() as c:
            existing=c.execute(select(users.c.id).where(users.c.email==email)).scalar_one_or_none()
            if existing is not None:
                raise HTTPException(409,'An account with this email already exists.')
            employee_id=c.execute(
                insert(users).values(
                    name=name,email=email,password=hash_password(data.password),role=data.role
                ).returning(users.c.id)
            ).scalar_one()
            c.execute(insert(employee_profiles).values(
                user_id=employee_id,designation=designation,department=department,
                is_active=1,created_by=user['id'],created_at=now
            ))
            c.execute(insert(employee_events).values(
                actor_id=user['id'],employee_id=employee_id,
                action=f"Employee created as {data.role}: {designation}",created_at=now
            ))
    except HTTPException:
        raise
    except Exception as exc:
        from sqlalchemy.exc import IntegrityError
        if isinstance(exc,IntegrityError):
            raise HTTPException(409,'An account with this email already exists.')
        raise
    return {
        'id':employee_id,'name':name,'email':email,'role':data.role,
        'designation':designation,'department':department,'is_active':True,
        'is_manager':False
    }

@app.patch('/api/employees/{employee_id}')
def update_employee(employee_id:int,data:UpdateEmployee,user=Depends(current_user)):
    require_employee_manager(user)
    changes=data.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(422,'Provide at least one field to update.')
    with db() as c:
        target=c.execute(
            select(users,employee_profiles.c.designation,employee_profiles.c.department,
                   employee_profiles.c.is_active,employee_managers.c.user_id.label('manager_id'))
            .join(employee_profiles,employee_profiles.c.user_id==users.c.id)
            .outerjoin(employee_managers,employee_managers.c.user_id==users.c.id)
            .where(users.c.id==employee_id,users.c.role.in_(('agent','admin')))
        ).mappings().first()
        if not target:
            raise HTTPException(404,'Employee not found.')
        is_manager=target['manager_id']==employee_id

        if is_manager and changes.get('role','admin')!='admin':
            raise HTTPException(409,'Transfer Employee Manager access before changing this person from Admin.')
        if is_manager and changes.get('is_active') is False:
            raise HTTPException(409,'Transfer Employee Manager access before deactivating this person.')
        if 'name' in changes:
            changes['name']=changes['name'].strip()
            if len(changes['name'])<2: raise HTTPException(422,'Name is too short.')
        profile_values={}
        for key in ('designation','department'):
            if key in changes:
                value=changes[key].strip() if changes[key] else None
                if key=='designation' and (value is None or len(value)<2):
                    raise HTTPException(422,'Designation must contain at least two characters.')
                profile_values[key]=value
        if 'role' in changes:
            c.execute(update(users).where(users.c.id==employee_id).values(role=changes['role']))
        if 'name' in changes:
            c.execute(update(users).where(users.c.id==employee_id).values(name=changes['name']))
        if 'is_active' in changes:
            profile_values['is_active']=1 if changes['is_active'] else 0
            if not changes['is_active']:
                c.execute(delete(sessions).where(sessions.c.user_id==employee_id))
        if profile_values:
            c.execute(update(employee_profiles).where(
                employee_profiles.c.user_id==employee_id
            ).values(**profile_values))
        now=int(time.time())
        summary=', '.join(sorted(changes.keys()))
        c.execute(insert(employee_events).values(
            actor_id=user['id'],employee_id=employee_id,
            action='Employee updated: '+summary,created_at=now
        ))
        updated=c.execute(
            select(users.c.id,users.c.name,users.c.email,users.c.role,
                   employee_profiles.c.designation,employee_profiles.c.department,
                   employee_profiles.c.is_active,employee_managers.c.user_id.label('manager_id'))
            .join(employee_profiles,employee_profiles.c.user_id==users.c.id)
            .outerjoin(employee_managers,employee_managers.c.user_id==users.c.id)
            .where(users.c.id==employee_id)
        ).mappings().one()
    return {
        'id':updated['id'],'name':updated['name'],'email':updated['email'],'role':updated['role'],
        'designation':updated['designation'],'department':updated['department'],
        'is_active':bool(updated['is_active']),'is_manager':updated['manager_id']==updated['id']
    }

@app.post('/api/employees/manager')
def transfer_employee_manager(data:TransferEmployeeManager,user=Depends(current_user)):
    require_employee_manager(user)
    now=int(time.time())
    with db() as c:
        target=c.execute(
            select(users.c.id,employee_profiles.c.is_active)
            .join(employee_profiles,employee_profiles.c.user_id==users.c.id)
            .where(users.c.id==data.user_id,users.c.role=='admin')
        ).mappings().first()
        if not target or not target['is_active']:
            raise HTTPException(422,'The new Employee Manager must be an active Admin employee.')
        if target['id']==user['id']:
            raise HTTPException(422,'This person already has Employee Manager access.')
        result=c.execute(
            update(employee_managers).where(employee_managers.c.singleton_id==1).values(
                user_id=target['id'],granted_by=user['id'],granted_at=now
            )
        )
        if result.rowcount!=1:
            raise HTTPException(409,'Employee Manager assignment is not configured. Contact system support.')
        c.execute(insert(employee_events).values(
            actor_id=user['id'],employee_id=target['id'],
            action='Employee Manager access transferred',created_at=now
        ))
    return {'ok':True,'manager_id':target['id']}

@app.post('/api/logout')
def logout(response:Response,session:str|None=Cookie(default=None)):
    with db() as c:
        if session: c.execute(delete(sessions).where(sessions.c.token==hashlib.sha256(session.encode()).hexdigest()))
    response.delete_cookie('session')
    return {'ok':True}

@app.get('/api/me')
def me(user=Depends(current_user)): return user

@app.post('/api/me/password')
def password_change(data:PasswordChange,response:Response,user=Depends(current_user)):
    with db() as c:
        stored=c.execute(select(users.c.password).where(users.c.id==user['id'])).scalar_one()
        if not check_password(data.current_password,stored): raise HTTPException(400,'Current password is incorrect')
        if data.new_password==data.current_password: raise HTTPException(422,'Choose a different password')
        c.execute(update(users).where(users.c.id==user['id']).values(password=hash_password(data.new_password)))
        c.execute(delete(sessions).where(sessions.c.user_id==user['id']))
    response.delete_cookie('session')
    return {'ok':True}

@app.get('/api/agents')
def agents(user=Depends(current_user)):
    if user['role']!='admin': raise HTTPException(403,'Administrator access required')
    with db() as c: return [dict(r) for r in c.execute(select(users.c.id,users.c.name).where(users.c.role=='agent')).mappings()]

@app.get('/api/stats')
def stats(user=Depends(current_user)):
    now=int(time.time())
    with db() as c:
        counts=dict(c.execute(select(ticket_table.c.status,func.count()).where(scope(user)).group_by(ticket_table.c.status)).all())
        overdue=c.execute(select(func.count()).select_from(ticket_table).where(scope(user),ticket_table.c.status!='resolved',ticket_table.c.due_at<now)).scalar_one()
        assigned=c.execute(select(func.count()).select_from(ticket_table).where(scope(user),ticket_table.c.assignee_id==user['id'],ticket_table.c.status!='resolved')).scalar_one()
        recent=[dict(r) for r in c.execute(select(audit_events.c.action,audit_events.c.created_at,audit_events.c.ticket_id,users.c.name.label('actor_name'),ticket_table.c.title).join(ticket_table,audit_events.c.ticket_id==ticket_table.c.id).join(users,audit_events.c.actor_id==users.c.id).where(scope(user)).order_by(audit_events.c.id.desc()).limit(6)).mappings()]
    return {'counts':{s:counts.get(s,0) for s in ('open','in_progress','resolved')},'total':sum(counts.values()),'overdue':overdue,'assigned_to_me':assigned,'activity':recent}

@app.get('/api/tickets')
def tickets(q:str=Query('',max_length=100),status:Literal['open','in_progress','resolved']|None=None,
            priority:Literal['low','medium','high']|None=None,mine:bool=False,overdue:bool=False,
            sort:Literal['updated','oldest','priority']='updated',offset:int=Query(0,ge=0),limit:int=Query(30,ge=1,le=100),user=Depends(current_user)):
    conditions=[scope(user)]
    if status: conditions.append(ticket_table.c.status==status)
    if priority: conditions.append(ticket_table.c.priority==priority)
    if mine: conditions.append(ticket_table.c.assignee_id==user['id'])
    if overdue: conditions.extend([ticket_table.c.status!='resolved',ticket_table.c.due_at<int(time.time())])
    if q:
        escaped=q.lower().replace('\\','\\\\').replace('%','\\%').replace('_','\\_')
        conditions.append(or_(func.lower(ticket_table.c.title).like('%'+escaped+'%',escape='\\'),func.lower(ticket_table.c.description).like('%'+escaped+'%',escape='\\')))
    order={'updated':[ticket_table.c.updated_at.desc(),ticket_table.c.id.desc()], 'oldest':[ticket_table.c.created_at,ticket_table.c.id], 'priority':[case((ticket_table.c.priority=='high',0),(ticket_table.c.priority=='medium',1),else_=2),ticket_table.c.updated_at.desc(),ticket_table.c.id.desc()]}[sort]
    customer=users.alias('customer');agent=users.alias('agent')
    query=select(ticket_table,customer.c.name.label('customer_name'),agent.c.name.label('assignee_name')).join(customer,ticket_table.c.customer_id==customer.c.id).outerjoin(agent,ticket_table.c.assignee_id==agent.c.id)
    with db() as c:
        total=c.execute(select(func.count()).select_from(ticket_table).where(*conditions)).scalar_one()
        rows=c.execute(query.where(*conditions).order_by(*order).limit(limit).offset(offset)).mappings()
        return {'items':[dict(r) for r in rows],'total':total}

@app.get('/api/export.xlsx')
def export_excel(q:str=Query('',max_length=100),status:Literal['open','in_progress','resolved']|None=None,
                 priority:Literal['low','medium','high']|None=None,mine:bool=False,overdue:bool=False,
                 sort:Literal['updated','oldest','priority']='updated',user=Depends(current_user)):
    if user['role'] not in ('agent','admin'): raise HTTPException(403,'Staff access required')
    from io import BytesIO
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill
    # Fetch the complete filtered result, independently of the UI page.
    result=tickets(q,status,priority,mine,overdue,sort,0,5001,user)
    if result['total']>5000: raise HTTPException(413,'Narrow your filters to 5,000 tickets or fewer.')
    book=Workbook();sheet=book.active;sheet.title='Tickets'
    fields=['id','title','description','status','priority','category','customer_name','assignee_name','created_at','updated_at','due_at']
    sheet.append(['Ticket ID','Subject','Description','Status','Priority','Category','Customer','Assigned agent','Created (UTC)','Updated (UTC)','Due (UTC)'])
    from datetime import datetime, timezone
    for item in result['items']:
        values=[]
        for key in fields:
            value=item[key]
            if key.endswith('_at') and value is not None: value=datetime.fromtimestamp(value,timezone.utc).replace(tzinfo=None)
            values.append(value)
        sheet.append(values)
        for cell in sheet[sheet.max_row]:
            # Force user content to literal text, never executable Excel formulas.
            if isinstance(cell.value,str): cell.data_type='s';cell.quotePrefix=True
            elif isinstance(cell.value,datetime): cell.number_format='yyyy-mm-dd hh:mm'
    sheet.freeze_panes='A2';sheet.auto_filter.ref=sheet.dimensions
    for cell in sheet[1]: cell.font=Font(bold=True,color='FFFFFF');cell.fill=PatternFill('solid',fgColor='16324F')
    for col,width in [('A',12),('B',45),('C',65),('D',18),('E',14),('F',16),('G',24),('H',24),('I',24),('J',24),('K',24)]: sheet.column_dimensions[col].width=width
    output=BytesIO();book.save(output)
    return Response(output.getvalue(),media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',headers={'Content-Disposition':'attachment; filename="supportdesk-tickets.xlsx"'})

@app.post('/api/tickets',status_code=201)
def create_ticket(data:NewTicket,user=Depends(current_user)):
    now=int(time.time())
    with db() as c:
        ticket_id=c.execute(insert(ticket_table).values(title=data.title.strip(),description=data.description.strip(),priority=data.priority,category=data.category,customer_id=user['id'],created_at=now,updated_at=now,due_at=now+SLA_HOURS[data.priority]*3600).returning(ticket_table.c.id)).scalar_one()
        audit(c,ticket_id,user['id'],'Ticket created')
        return ticket_for(c,ticket_id,user)

@app.get('/api/tickets/{ticket_id}')
def detail(ticket_id:int,user=Depends(current_user)):
    with db() as c:
        t=ticket_for(c,ticket_id,user)
        t['customer_name']=c.execute(select(users.c.name).where(users.c.id==t['customer_id'])).scalar_one()
        t['assignee_name']=c.execute(select(users.c.name).where(users.c.id==t['assignee_id'])).scalar_one_or_none()
        t['comments']=[dict(r) for r in c.execute(select(comments,users.c.name.label('author_name'),users.c.role.label('author_role')).join(users,comments.c.author_id==users.c.id).where(comments.c.ticket_id==ticket_id).order_by(comments.c.id)).mappings()]
        t['audit']=[dict(r) for r in c.execute(select(audit_events,users.c.name.label('actor_name')).join(users,audit_events.c.actor_id==users.c.id).where(audit_events.c.ticket_id==ticket_id).order_by(audit_events.c.id)).mappings()]
        return t

@app.patch('/api/tickets/{ticket_id}/status')
def change_status(ticket_id:int,data:UpdateTicket,user=Depends(current_user)):
    with db() as c:
        t=ticket_for(c,ticket_id,user,write=True)
        if user['role']=='customer': raise HTTPException(403,'Agents manage ticket status')
        allowed={'open':{'in_progress'},'in_progress':{'resolved','open'},'resolved':{'open'}}
        if data.status not in allowed[t['status']]: raise HTTPException(409,'Invalid status transition')
        mutate(c,t,data,{'status':data.status})
        audit(c,ticket_id,user['id'],f"Status: {t['status']} → {data.status}")
        return ticket_for(c,ticket_id,user)

@app.patch('/api/tickets/{ticket_id}/assignment')
def assign(ticket_id:int,data:Assignment,user=Depends(current_user)):
    if user['role']!='admin': raise HTTPException(403,'Administrator access required')
    with db() as c:
        t=ticket_for(c,ticket_id,user)
        agent=c.execute(select(users).where(users.c.id==data.assignee_id,users.c.role=='agent')).mappings().first()
        if data.assignee_id is not None and not agent: raise HTTPException(422,'Assignee must be an agent')
        mutate(c,t,data,{'assignee_id':data.assignee_id})
        audit(c,ticket_id,user['id'],'Assigned to '+agent['name'] if agent else 'Assignment removed')
        return ticket_for(c,ticket_id,user)

@app.post('/api/tickets/{ticket_id}/comments',status_code=201)
def comment(ticket_id:int,data:Comment,user=Depends(current_user)):
    with db() as c:
        t=ticket_for(c,ticket_id,user,write=True)
        # Conditional update protects against assignment changing between authorization and write.
        mutate(c,t,UpdateTicket(status=t['status'],version=t['version']),{})
        c.execute(insert(comments).values(ticket_id=ticket_id,author_id=user['id'],body=data.body.strip(),created_at=int(time.time())))
        audit(c,ticket_id,user['id'],'Comment added')
    return {'ok':True}

@app.get('/health')
def health():
    with db() as c: c.execute(select(users.c.id).limit(1))
    return {'status':'ok','application':'SupportDesk','database':engine().dialect.name}
@app.get('/')
def index(): return FileResponse(STATIC/'index.html')
app.mount('/static',StaticFiles(directory=STATIC),name='static')
