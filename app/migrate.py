"""Idempotent v1→v2 migration; preserves IDs, passwords, tickets and history."""
import re
from sqlalchemy import inspect, select, insert, update, text
from .database import metadata, versions, users, tickets, comments

def migrate(engine):
    metadata.create_all(engine)
    with engine.begin() as c:
        if c.execute(select(versions.c.version).where(versions.c.version==2)).first(): return
        columns={col['name'] for col in inspect(c).get_columns('tickets')}
        for name,definition in [('category',"VARCHAR(30) NOT NULL DEFAULT 'general'"),('due_at','INTEGER'),('version','INTEGER NOT NULL DEFAULT 1')]:
            if name not in columns: c.execute(text(f'ALTER TABLE tickets ADD COLUMN {name} {definition}'))
        for index in tickets.indexes: index.create(c,checkfirst=True)
        for old,new in [('customer','customer'),('other','customer2'),('agent','agent'),('admin','admin')]:
            old_row=c.execute(select(users.c.id).where(users.c.email==old+'@demo.local')).first()
            exists=c.execute(select(users.c.id).where(users.c.email==new+'@assistflow.local')).first()
            if old_row and not exists: c.execute(update(users).where(users.c.id==old_row[0]).values(email=new+'@assistflow.local'))
        # Remove only the tutorial's explicit prefix, retaining all content and records.
        for row in c.execute(select(tickets.c.id,tickets.c.title,tickets.c.description)).mappings().all():
            title=re.sub(r'^DEMO \d{2}:\d{2}:\d{2} - ','',row['title'])
            description=row['description'].removeprefix('DEMO ONLY: ')
            if title!=row['title'] or description!=row['description']:
                c.execute(update(tickets).where(tickets.c.id==row['id']).values(title=title,description=description))
        for row in c.execute(select(comments.c.id,comments.c.body).where(comments.c.body.like('DEMO: %'))).mappings().all():
            c.execute(update(comments).where(comments.c.id==row['id']).values(body=row['body'].removeprefix('DEMO: ')))
        # Historical records have no retroactive SLA. Targets begin on new requests.
        c.execute(insert(versions).values(version=2))

if __name__=='__main__':
    from .main import engine
    migrate(engine())
    print('AssistFlow schema v2 ready; existing data preserved.')
