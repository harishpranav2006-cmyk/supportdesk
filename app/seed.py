"""Explicit local account setup. No built-in credentials."""
import os
from sqlalchemy import select, insert
from .main import db,hash_password,init_db
from .database import users

def main():
    password=os.environ.get('ASSISTFLOW_INITIAL_PASSWORD')
    if not password or len(password)<12:
        raise SystemExit('Set ASSISTFLOW_INITIAL_PASSWORD to a password of at least 12 characters.')
    init_db()
    with db() as c:
        for email,name,role in [('customer','Harish','customer'),('customer2','Second customer','customer'),('agent','Priya','agent'),('admin','Administrator','admin')]:
            address=email+'@assistflow.local'
            if not c.execute(select(users.c.id).where(users.c.email==address)).first():
                c.execute(insert(users).values(email=address,name=name,password=hash_password(password),role=role))
    print('AssistFlow local accounts ready. Existing passwords retained; use Account settings to change yours.')
if __name__=='__main__': main()
