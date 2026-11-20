"""Portable SQLAlchemy schema. SQLite locally; PostgreSQL via DATABASE_URL."""
import os
from functools import lru_cache
from sqlalchemy import (MetaData, Table, Column, Integer, String, Text, ForeignKey,
                        CheckConstraint, Index, create_engine, event)
metadata = MetaData()
users = Table('users',metadata,Column('id',Integer,primary_key=True),Column('email',String(254),nullable=False,unique=True),Column('name',String(100),nullable=False),Column('password',Text,nullable=False),Column('role',String(20),nullable=False),CheckConstraint("role IN ('customer','agent','admin')"))
sessions = Table('sessions',metadata,Column('token',String(64),primary_key=True),Column('user_id',Integer,ForeignKey('users.id'),nullable=False),Column('expires',Integer,nullable=False))
tickets = Table('tickets',metadata,Column('id',Integer,primary_key=True),Column('title',String(160),nullable=False),Column('description',Text,nullable=False),Column('priority',String(20),nullable=False),Column('status',String(20),nullable=False,server_default='open'),Column('customer_id',Integer,ForeignKey('users.id'),nullable=False),Column('assignee_id',Integer,ForeignKey('users.id')),Column('created_at',Integer,nullable=False),Column('updated_at',Integer,nullable=False),Column('category',String(30),nullable=False,server_default='general'),Column('due_at',Integer),Column('version',Integer,nullable=False,server_default='1'),CheckConstraint("priority IN ('low','medium','high')"),CheckConstraint("status IN ('open','in_progress','resolved')"))
comments = Table('comments',metadata,Column('id',Integer,primary_key=True),Column('ticket_id',Integer,ForeignKey('tickets.id'),nullable=False),Column('author_id',Integer,ForeignKey('users.id'),nullable=False),Column('body',Text,nullable=False),Column('created_at',Integer,nullable=False))
audit_events = Table('audit',metadata,Column('id',Integer,primary_key=True),Column('ticket_id',Integer,ForeignKey('tickets.id'),nullable=False),Column('actor_id',Integer,ForeignKey('users.id'),nullable=False),Column('action',Text,nullable=False),Column('created_at',Integer,nullable=False))
login_attempts = Table('login_attempts',metadata,Column('email',String(254),primary_key=True),Column('failures',Integer,nullable=False),Column('reset_at',Integer,nullable=False))
signup_attempts = Table('signup_attempts',metadata,Column('ip',String(64),primary_key=True),Column('attempts',Integer,nullable=False),Column('reset_at',Integer,nullable=False))
versions = Table('schema_versions',metadata,Column('version',Integer,primary_key=True))
Index('ticket_customer_updated',tickets.c.customer_id,tickets.c.updated_at)
Index('ticket_status_updated',tickets.c.status,tickets.c.updated_at)
Index('ticket_assignee_status',tickets.c.assignee_id,tickets.c.status)
Index('ticket_due',tickets.c.status,tickets.c.due_at)
Index('comment_ticket_id',comments.c.ticket_id,comments.c.id)
Index('audit_ticket_id',audit_events.c.ticket_id,audit_events.c.id)
Index('session_expiry',sessions.c.expires)

@lru_cache(maxsize=8)
def engine_for(url):
    if url.startswith('postgres://'): url=url.replace('postgres://','postgresql+psycopg://',1)
    if url.startswith('postgresql://'): url=url.replace('postgresql://','postgresql+psycopg://',1)
    engine=create_engine(url,pool_pre_ping=True,**({'connect_args':{'check_same_thread':False,'timeout':15}} if url.startswith('sqlite:') else {'pool_size':5,'max_overflow':10}))
    if engine.dialect.name=='sqlite':
        @event.listens_for(engine,'connect')
        def configure(con,_):
            con.execute('PRAGMA foreign_keys=ON')
            con.execute('PRAGMA journal_mode=WAL')
    return engine
