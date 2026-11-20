import tempfile
import unittest
from pathlib import Path
from fastapi.testclient import TestClient
from app import main as m

class SupportDeskTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        m.DB_PATH=str(Path(self.tmp.name)/'test.db')
        m.init_db()
        with m.db() as c:
            for email,role in [('one','customer'),('two','customer'),('agent','agent'),('admin','admin'),('admin2','admin'),('agent2','agent')]:
                c.execute(m.insert(m.users).values(email=email+'@test.local',name=email,password=m.hash_password('test-password-123'),role=role))
            staff=c.execute(m.select(m.users.c.id,m.users.c.role).where(m.users.c.role.in_(('agent','admin')))).all()
            for person_id,role in staff:
                c.execute(m.insert(m.employee_profiles).values(
                    user_id=person_id,
                    designation='Administrator' if role=='admin' else 'Support Agent',
                    department='Support',
                    is_active=1,
                    created_by=None,
                    created_at=0,
                ))
            manager_id=c.execute(m.select(m.users.c.id).where(m.users.c.email=='admin@test.local')).scalar_one()
            c.execute(m.insert(m.employee_managers).values(
                singleton_id=1,user_id=manager_id,granted_by=manager_id,granted_at=0
            ))
        self.client=TestClient(m.app)
    def tearDown(self):
        self.client.close();m.engine().dispose();self.tmp.cleanup()
    def login(self,name):
        self.client.cookies.clear()
        r=self.client.post('/api/login',json={'email':name+'@test.local','password':'test-password-123'})
        self.assertEqual(r.status_code,200)
    def ticket(self):
        self.login('one')
        r=self.client.post('/api/tickets',json={'title':'Cannot sign in','description':'The password reset link fails.'})
        self.assertEqual(r.status_code,201)
        return r.json()['id']
    def test_requires_authentication(self):
        self.assertEqual(self.client.get('/api/tickets').status_code,401)
    def test_customer_isolation_all_paths(self):
        tid=self.ticket();self.login('two')
        self.assertEqual(self.client.get('/api/tickets').json()['total'],0)
        self.assertEqual(self.client.get(f'/api/tickets/{tid}').status_code,404)
        self.assertEqual(self.client.post(f'/api/tickets/{tid}/comments',json={'body':'attack'}).status_code,404)
        self.assertEqual(self.client.patch(f'/api/tickets/{tid}/status',json={'status':'in_progress'}).status_code,404)
    def test_customer_cannot_assign_or_change_status(self):
        tid=self.ticket()
        self.assertEqual(self.client.patch(f'/api/tickets/{tid}/assignment',json={'assignee_id':3}).status_code,403)
        self.assertEqual(self.client.patch(f'/api/tickets/{tid}/status',json={'status':'in_progress'}).status_code,403)
    def test_assignment_status_and_audit(self):
        tid=self.ticket();self.login('agent')
        self.assertEqual(self.client.patch(f'/api/tickets/{tid}/status',json={'status':'in_progress'}).status_code,403)
        self.login('admin')
        self.assertEqual(self.client.patch(f'/api/tickets/{tid}/assignment',json={'assignee_id':1}).status_code,422)
        self.assertEqual(self.client.patch(f'/api/tickets/{tid}/assignment',json={'assignee_id':3}).status_code,200)
        self.login('agent2')
        self.assertEqual(self.client.post(f'/api/tickets/{tid}/comments',json={'body':'No permission'}).status_code,403)
        self.login('agent')
        for status,code in [('resolved',409),('in_progress',200),('resolved',200),('open',200)]:
            self.assertEqual(self.client.patch(f'/api/tickets/{tid}/status',json={'status':status}).status_code,code)
        self.assertEqual(len(self.client.get(f'/api/tickets/{tid}').json()['audit']),5)
    def test_comment_and_logout(self):
        tid=self.ticket()
        self.assertEqual(self.client.post(f'/api/tickets/{tid}/comments',json={'body':'More details'}).status_code,201)
        self.assertEqual(self.client.get(f'/api/tickets/{tid}').json()['comments'][0]['body'],'More details')
        cookie=self.client.cookies.get('session')
        self.client.post('/api/logout',json={})
        self.client.cookies.set('session',cookie)
        self.assertEqual(self.client.get('/api/me').status_code,401)
    def test_validation_filters_and_pagination(self):
        self.ticket()
        self.assertEqual(self.client.post('/api/tickets',json={'title':'   ','description':'      '}).status_code,422)
        self.assertEqual(self.client.get('/api/tickets?q=sign').json()['total'],1)
        self.assertEqual(self.client.get('/api/tickets?q=%27%20OR%201=1').json()['total'],0)
        self.assertEqual(self.client.get('/api/tickets?offset=1').json()['items'],[])
        self.assertEqual(self.client.get('/api/tickets?limit=1000').status_code,422)
    def test_login_throttle_and_expired_session(self):
        for i in range(5):
            self.assertEqual(self.client.post('/api/login',json={'email':'one@test.local','password':'wrong'}).status_code,401)
        self.assertEqual(self.client.post('/api/login',json={'email':'one@test.local','password':'test-password-123'}).status_code,429)
        self.login('two')
        with m.db() as c:c.execute(m.update(m.sessions).values(expires=0))
        self.assertEqual(self.client.get('/api/me').status_code,401)
    def test_export_permissions_filters_and_literal_text(self):
        self.assertEqual(self.client.get('/api/export.xlsx').status_code,401)
        self.ticket()
        self.assertEqual(self.client.get('/api/export.xlsx').status_code,403)
        self.client.post('/api/tickets',json={'title':'=HYPERLINK("evil")','description':'+dangerous text'})
        from io import BytesIO
        from openpyxl import load_workbook
        for role in ('agent','admin'):
            self.login(role)
            response=self.client.get('/api/export.xlsx?q=HYPERLINK')
            self.assertEqual(response.status_code,200)
            sheet=load_workbook(BytesIO(response.content)).active
            self.assertEqual(sheet.max_row,2)
            self.assertEqual(sheet['B2'].data_type,'s')
            self.assertEqual(sheet['B2'].value,'=HYPERLINK("evil")')
    def test_stale_update_and_stats_scope(self):
        tid=self.ticket();self.login('two')
        self.assertEqual(self.client.get('/api/stats').json()['total'],0)
        self.login('admin')
        self.assertEqual(self.client.patch(f'/api/tickets/{tid}/assignment',json={'assignee_id':3,'version':1}).status_code,200)
        self.assertEqual(self.client.patch(f'/api/tickets/{tid}/status',json={'status':'in_progress','version':1}).status_code,409)
    def test_password_change_revokes_sessions(self):
        self.login('one')
        self.assertEqual(self.client.post('/api/me/password',json={'current_password':'test-password-123','new_password':'changed-password-123'}).status_code,200)
        self.assertEqual(self.client.get('/api/me').status_code,401)

    def test_security_headers_and_cross_site_write(self):
        self.assertEqual(self.client.get('/').status_code,200)
        self.assertIn('frame-ancestors',self.client.get('/').headers['content-security-policy'])
        self.assertEqual(self.client.post('/api/logout',json={},headers={'sec-fetch-site':'cross-site'}).status_code,403)
        self.assertEqual(self.client.post('/api/logout',data='test').status_code,415)


    def test_public_registration_creates_customer_session_and_hashes_password(self):
        response=self.client.post('/api/register',json={
            'name':'New Customer',
            'email':'New.Customer@SupportDesk.Local',
            'password':'customer-signup-pass-123',
            'role':'admin',
        })
        self.assertEqual(response.status_code,201)
        account=response.json()
        self.assertEqual(account['email'],'new.customer@supportdesk.local')
        self.assertEqual(account['role'],'customer')
        self.assertEqual(self.client.get('/api/me').status_code,200)
        self.assertEqual(self.client.get('/api/me').json()['role'],'customer')
        with m.db() as c:
            stored=c.execute(m.select(m.users.c.password).where(
                m.users.c.email=='new.customer@supportdesk.local'
            )).scalar_one()
        self.assertNotEqual(stored,'customer-signup-pass-123')
        self.assertTrue(m.check_password('customer-signup-pass-123',stored))

    def test_public_registration_rejects_duplicate_email_case_insensitively(self):
        payload={'name':'New Customer','email':'new@supportdesk.local','password':'customer-signup-pass-123'}
        self.assertEqual(self.client.post('/api/register',json=payload).status_code,201)
        payload['email']='NEW@SUPPORTDESK.LOCAL'
        self.assertEqual(self.client.post('/api/register',json=payload).status_code,409)

    def test_public_registration_validates_inputs(self):
        base={'name':'New Customer','email':'new@supportdesk.local','password':'short'}
        self.assertEqual(self.client.post('/api/register',json=base).status_code,422)
        base['password']='customer-signup-pass-123'
        base['email']='not-an-email'
        self.assertEqual(self.client.post('/api/register',json=base).status_code,422)

    def test_public_registration_is_rate_limited_per_client(self):
        for i in range(5):
            response=self.client.post('/api/register',json={
                'name':'New Customer',
                'email':f'customer{i}@supportdesk.local',
                'password':'customer-signup-pass-123',
            })
            self.assertEqual(response.status_code,201)
        blocked=self.client.post('/api/register',json={
            'name':'Another Customer',
            'email':'blocked@supportdesk.local',
            'password':'customer-signup-pass-123',
        })
        self.assertEqual(blocked.status_code,429)


    def test_employee_manager_can_create_agent_and_admin_with_designations(self):
        self.login('admin')
        response=self.client.post('/api/employees',json={
            'name':'Taylor Employee',
            'email':'taylor@supportdesk.local',
            'password':'temporary-password-123',
            'role':'agent',
            'designation':'Senior Support Engineer',
            'department':'Technical Support',
        })
        self.assertEqual(response.status_code,201)
        created=response.json()
        self.assertEqual(created['role'],'agent')
        self.assertEqual(created['designation'],'Senior Support Engineer')
        self.assertEqual(created['department'],'Technical Support')
        self.assertFalse(created['is_manager'])
        listing=self.client.get('/api/employees')
        self.assertEqual(listing.status_code,200)
        self.assertTrue(any(x['email']=='taylor@supportdesk.local' for x in listing.json()))

    def test_only_designated_manager_can_access_employee_administration(self):
        self.login('one')
        self.assertEqual(self.client.get('/api/employees').status_code,403)
        self.login('agent')
        self.assertEqual(self.client.get('/api/employees').status_code,403)
        self.login('admin2')
        self.assertEqual(self.client.get('/api/employees').status_code,403)
        self.assertEqual(self.client.post('/api/employees',json={
            'name':'Blocked Employee','email':'blocked@supportdesk.local',
            'password':'temporary-password-123','role':'admin',
            'designation':'Administrator','department':'Operations'
        }).status_code,403)

    def test_employee_manager_can_edit_designation_and_deactivate_account(self):
        self.login('admin')
        created=self.client.post('/api/employees',json={
            'name':'Taylor Employee','email':'taylor@supportdesk.local',
            'password':'temporary-password-123','role':'agent',
            'designation':'Support Agent','department':'Support'
        }).json()
        staff_client=TestClient(m.app)
        signed=staff_client.post('/api/login',json={
            'email':'taylor@supportdesk.local','password':'temporary-password-123'
        })
        self.assertEqual(signed.status_code,200)
        changed=self.client.patch('/api/employees/'+str(created['id']),json={
            'designation':'Lead Support Engineer','department':'Technical Support'
        })
        self.assertEqual(changed.status_code,200)
        self.assertEqual(changed.json()['designation'],'Lead Support Engineer')
        inactive=self.client.patch('/api/employees/'+str(created['id']),json={'is_active':False})
        self.assertEqual(inactive.status_code,200)
        self.assertFalse(inactive.json()['is_active'])
        self.assertEqual(staff_client.get('/api/me').status_code,401)
        self.assertIn(staff_client.post('/api/login',json={
            'email':'taylor@supportdesk.local','password':'temporary-password-123'
        }).status_code,(401,429))
        staff_client.close()

    def test_employee_manager_can_transfer_single_manager_permission(self):
        self.login('admin')
        transfer=self.client.post('/api/employees/manager',json={'user_id':5})
        self.assertEqual(transfer.status_code,200)
        self.assertEqual(self.client.get('/api/employees').status_code,403)
        self.login('admin2')
        self.assertEqual(self.client.get('/api/employees').status_code,200)
        self.assertTrue(any(x['is_manager'] for x in self.client.get('/api/employees').json()))

    def test_employee_manager_cannot_deactivate_or_demote_themselves(self):
        self.login('admin')
        manager_id=self.client.get('/api/me').json()['id']
        self.assertEqual(self.client.patch(f'/api/employees/{manager_id}',json={'is_active':False}).status_code,409)
        self.assertEqual(self.client.patch(f'/api/employees/{manager_id}',json={'role':'agent'}).status_code,409)

if __name__=='__main__':unittest.main()
