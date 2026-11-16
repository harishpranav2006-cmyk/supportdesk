"""Explicit local-demo bootstrap. Never runs automatically on deployment."""
import os
from .main import db, hash_password, init_db

def main():
    password=os.environ.get('DEMO_PASSWORD')
    if not password or len(password)<12:
        raise SystemExit('Set DEMO_PASSWORD to a password of at least 12 characters first.')
    init_db()
    with db() as c:
        for email,name,role in [('customer@demo.local','Harish','customer'),('other@demo.local','Second customer','customer'),('agent@demo.local','Priya','agent'),('admin@demo.local','Administrator','admin')]:
            c.execute('INSERT OR IGNORE INTO users(email,name,password,role) VALUES (?,?,?,?)',(email,name,hash_password(password),role))
    print('Demo accounts ready: customer@demo.local, other@demo.local, agent@demo.local, admin@demo.local')
    print('Existing accounts retain their passwords. This database is for local demonstration only.')

if __name__=='__main__': main()
