import unittest
import time

from pynessus.nessus import Nessus
from pynessus.models.user import User
from pynessus.models.policy import Policy
from pynessus.models.scan import Scan
from pynessus.models.schedule import Schedule, Frequencies
from pynessus.models.tag import Tag

class TestServer(unittest.TestCase):
    """
    Test suite.
    """

    def setUp(self):
        self.server = Nessus("localhost")
        self.user = User("user", "password")
        self.connected = False

    def tearDown(self):
        if self.connected:
            self.assertTrue(self.server.logout())

    def login(self):
        self.assertTrue(self.server.login(self.user))
        self.connected = True

    def test_load_properties(self):
        if not self.connected:
            self.login()
        self.assertTrue(self.server.load_properties())

    def test_load_scans(self):
        if not self.connected:
            self.login()
        self.assertTrue(self.server.load_scans())

    def test_load_tags(self):
        if not self.connected:
            self.login()
        self.assertTrue(self.server.load_tags())

    def test_load_policies(self):
        if not self.connected:
            self.login()
        self.assertTrue(self.server.load_policies())

    def test_load_users(self):
        if not self.connected:
            self.login()
        self.assertTrue(self.server.load_users())

    def test_load_reports(self):
        if not self.connected:
            self.login()
        self.assertTrue(self.server.load_reports())

    def test_scan(self):
        if not self.connected:
            self.login()
        self.server.load_policies()
        scan = Scan()
        scan.name = "My new scan"
        if len(self.server.policies):
            scan.policy = self.server.policies[0]
            scan.custom_targets = "127.0.0.1"
        else:
            policy = Policy()
            policy.name = "My new policy"
            policy.description = "Policy description"
            self.assertTrue(self.server.create_policy(policy))
            scan.policy = policy

        self.server.create_scan(scan)
        time.sleep(5)
        self.assertTrue(self.server.pause_scan(scan))
        time.sleep(2)
        self.assertTrue(self.server.resume_scan(scan))
        time.sleep(2)
        self.assertTrue(self.server.stop_scan(scan))
        t = Tag()
        t.name = "Tag target"
        self.assertTrue(self.server.create_tag(t))
        self.assertTrue(self.server.move_scan(scan, t))
        self.assertTrue(self.server.set_scan_status(scan, "read"))
        self.assertTrue(self.server.stop_scan(scan))
        time.sleep(10)
        self.assertTrue(self.server.delete_scan(scan))

        #TODO scan diff testing

    def test_upload_file(self):
        if not self.connected:
            self.login()
        with open("/tmp/test.xml", "wb") as f:
            f.write("<xml></xml>")
        self.assertTrue(self.server.upload_file("/tmp/test.xml"))

    def test_report_download(self):
        if not self.connected:
            self.login()
        for report in self.server.reports:
            self.assertTrue(self.server.load_report(report, "nessus.v2"))
            self.assertTrue(report.save())
            self.assertTrue(self.server.load_report(report, "csv"))
            self.assertTrue(report.save())
            self.assertTrue(self.server.load_report(report, "html"))
            self.assertTrue(report.save())
            self.assertTrue(self.server.load_report(report, "pdf"))
            self.assertTrue(report.save())

    def test_policy(self):
        if not self.connected:
            self.login()
        policy = Policy()
        policy.name = "My new policy"
        policy.description = "Policy description"
        self.assertTrue(self.server.create_policy(policy))
        policy.description = "New description"
        self.assertTrue(self.server.update_policy(policy))
        self.assertTrue(self.server.get_policy_preferences(policy))
        self.assertTrue(self.server.get_policy_plugins(policy))
        copy_policy = self.server.copy_policy(policy)
        self.assertEqual(type(copy_policy), Policy)
        self.assertTrue(self.server.delete_policy(policy))
        self.assertTrue(self.server.delete_policy(copy_policy))

    def test_tag(self):
        if not self.connected:
            self.login()
        t = Tag()
        t.name = "My new tag"
        self.assertTrue(self.server.create_tag(t))
        t.name = "Updated name tag"
        self.assertTrue(self.server.update_tag(t))
        self.assertTrue(self.server.delete_tag(t))

    def test_schedule(self):
        if not self.connected:
            self.login()
        s = Schedule()
        s.name = "New schedule"
        s.description = "Schedule description"
        s.emails = "kaiserquentin@gmail.com"
        s.custom_targets = "127.0.0.1"

        self.server.load_tags()
        self.server.load_policies()
        s.tag = self.server.tags[0]
        s.policy = self.server.policies[0]
        s.rrules = Frequencies.DAILY
        s.starttime = int(time.time())+86400
        s.timezone = "Europe/Brussels"

        self.assertTrue(self.server.create_schedule(s))
        self.assertTrue(self.server.launch_schedule(s))
        self.assertTrue(self.server.update_schedule(s))
        self.assertTrue(self.server.delete_schedule(s))

    def test_user(self):
        if not self.connected:
            self.login()
        u = User()
        u.username = "Test"
        u.password = "test"
        u.permissions = 32
        self.assertTrue(self.server.create_user(u))
        u.permissions = 128
        self.assertTrue(self.server.update_user(u))
        self.assertEqual(u.permissions, 128)
        self.assertTrue(self.server.delete_user(u))
