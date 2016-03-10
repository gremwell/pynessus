import unittest
import random
import string
import json
from time import sleep

from pynessus.nessus import Nessus
from pynessus.models.policy import Policy
from pynessus.models.plugin import Severity
from pynessus.models.scan import Scan, FORMATS


def random_name(length):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(length))


class NessusTestCase(unittest.TestCase):

    def setUp(self):
        self.server = Nessus("localhost")
        user = self.server.User("quentin", "P@ssw0rd")
        self.server.login(user)
        self.connected = False

    def tearDown(self):
        if self.connected:
            self.assertTrue(self.server.logout())


class AgentsTestCase(NessusTestCase):
    """
    Agents test cases.
    """

    def test_load(self):
        """
        Tests Nessus agents loading.
        :return:
        """
        self.assertTrue(self.server.load_agents())

    def test_delete(self):
        """
        Test Nessus agents deletion
        :return:
        """
        self.assertTrue(self.server.load_agents())
        for agent in self.server.agents:
            self.assertTrue(agent.delete())


class AgentGroupsTestCase(NessusTestCase):
    """
    Agent groups test cases.
    """

    def test_load(self):
        """
        Tests Nessus agent groups loading
        :return:
        """
        self.assertTrue(self.server.load_agentgroups())

    def test_create(self):
        """
        Tests Nessus agent group creation.
        :return:
        """
        self.server.load_scanners()
        agent_group = self.server.AgentGroup()
        agent_group.name = random_name(8)
        agent_group.scanner_id = self.server.scanners[0].id
        self.assertTrue(agent_group.create())

    def test_update(self):
        """
        Tests Nessus agent group update.
        :return:
        """
        self.server.load_agentgroups()
        self.server.load_scanners()
        agent_group = self.server.AgentGroup()
        agent_group.name = random_name(8)
        agent_group.scanner_id = self.server.scanners[0].id
        self.assertTrue(agent_group.create())
        agent_group.name += " - updated"
        self.assertTrue(agent_group.update())

    def test_delete(self):
        """
        Tests Nessus agent groups deletion.
        :return:
        """
        self.server.load_agentgroups()
        for agent_group in self.server.agentgroups:
            self.assertTrue(agent_group.delete())

    def test_details(self):
        """
        Tests Nessus agent group details.
        :return:
        """
        self.server.load_agentgroups()
        for agent_group in self.server.agentgroups:
            self.assertTrue(agent_group.details())

    def test_add_remove_agent(self):
        """
        Tests Nessus agent group's agent addition and removal.
        :return:
        """
        # Create a new agent group
        self.server.load_scanners()
        agent_group = self.server.AgentGroup()
        agent_group.name = random_name(8)
        agent_group.scanner_id = self.server.scanners[0].id
        self.assertTrue(agent_group.create())

        # loop through all agents and add them to the new group
        self.server.load_agents()
        for agent in self.server.agents:
            self.assertTrue(agent_group.add_agent(agent.id))
            self.assertTrue(agent_group.remove_agent(agent.id))


class FilesTestCase(NessusTestCase):
    """
    Nessus file upload test cases.
    """

    def test_upload_file(self):
        """
        Tests Nessus file upload functionality.
        :return:
        """
        import tempfile
        t = tempfile.NamedTemporaryFile()
        t.write("Temporary file")
        self.assertTrue(self.server.upload_file(t.name))
        t.close()


class FoldersTestCase(NessusTestCase):
    """
    Nessus folders management test cases.
    """

    def test_create(self):
        """
        Tests Nessus folder creation.
        :return:
        """
        folder = self.server.Folder()
        folder.name = random_name(8)
        self.assertTrue(folder.create())

    def test_update(self):
        """
        Tests Nessus folder update.
        :return:
        """
        folder = self.server.Folder()
        folder.name = random_name(8)
        self.assertTrue(folder.create())
        folder.name = random_name(8)
        self.assertTrue(folder.edit())

    def test_delete(self):
        """
        Tests Nessus folder deletion.
        :return:
        """
        # load folders
        self.server.load_folders()

        # Delete all custome folders
        for folder in [f for f in self.server.folders if f.custom]:
            self.assertTrue(folder.delete())

        # Test that a specific error is thrown when trying to delete system folders.
        for folder in [f for f in self.server.folders if not f.custom]:
            with self.assertRaises(Exception) as context:
                folder.delete()
            self.assertEqual("Can not edit system folders", json.loads(str(context.exception))["error"])


# class GroupsTestCase(NessusTestCase):
#     """
#     Nessus groups management test cases.
#     """
#
#     def test_create(self):
#         """
#         Tests Nessus group creation
#         :return:
#         """
#         group = self.server.Group()
#         group.name = random_name(8)
#         self.assertTrue(group.create())
#
#     def test_edit(self):
#         """
#         Tests Nessus group edition
#         :return:
#         """
#         group = self.server.Group()
#         group.name = random_name(8)
#         self.assertTrue(group.create())
#         group.name = random_name(8)
#         self.assertTrue(group.edit())
#
#     def test_delete(self):
#         """
#         Tests Nessus group deletion
#         :return:
#         """
#         self.server.load_groups()
#         for group in self.server.groups:
#             self.assertTrue(group.delete())
#
#     def test_list_users(self):
#         """
#         Test Nessus group's users listing.
#         :return:
#         """
#         self.server.load_groups()
#         for group in self.server.groups:
#             self.assertTrue(group.list_users())
#
#     def test_add_remove_user(self):
#         """
#         Test Nessus group's user insertion.
#         :return:
#         """
#         group = self.server.Group()
#         group.name = random_name(8)
#         self.assertTrue(group.create())
#         user = self.server.User(random_name(8), "P@ssw0rd")
#         self.assertTrue(user.create())
#         self.assertTrue(group.add_user(user))
#         self.assertTrue(group.delete_user(user))
#         self.assertTrue(user.delete())


class MailTestCase(NessusTestCase):
    """
    Nessus mail settings test cases.
    """

    def test_view(self):
        """
        Tests Nessus mail settings view.
        :return:
        """
        self.assertTrue(self.server.load_mail())
        self.assertIsNotNone(self.server.mail.smtp_host)
        self.assertIsNotNone(self.server.mail.smtp_port)
        self.assertIsNotNone(self.server.mail.smtp_from)
        self.assertIsNotNone(self.server.mail.smtp_www_host)
        self.assertIsNotNone(self.server.mail.smtp_auth)
        self.assertIsNotNone(self.server.mail.smtp_pass)
        self.assertIsNotNone(self.server.mail.smtp_enc)

    def test_change(self):
        """
        Tests Nessus mail settings update.
        :return:
        """
        self.assertTrue(self.server.load_mail())

        self.server.mail.smtp_host = "localhost"
        self.server.mail.smtp_port = 25
        self.server.mail.smtp_from = "postmaster@localhost"
        self.server.mail.smtp_www_host = "localhost"
        self.server.mail.smtp_auth = "PLAIN"
        self.server.mail.smtp_user = "test"
        self.server.mail.smtp_pass = "test"
        self.server.mail.smtp_enc = "Force SSL"

        self.assertTrue(self.server.mail.update())

        self.assertTrue(self.server.load_mail())

        self.assertEqual(self.server.mail.smtp_host, "localhost")
        self.assertEqual(self.server.mail.smtp_port, 25)
        self.assertEqual(self.server.mail.smtp_from, "postmaster@localhost")
        self.assertEqual(self.server.mail.smtp_www_host, "localhost")
        self.assertEqual(self.server.mail.smtp_auth, "PLAIN")
        self.assertEqual(self.server.mail.smtp_user, "test")
        self.assertEqual(self.server.mail.smtp_pass, "********")
        self.assertEqual(self.server.mail.smtp_enc, "Force SSL")


class PermissionTestCase(NessusTestCase):
    """
    Nessus permissions test cases.
    """


class PluginTestCase(NessusTestCase):
    """
    Nessus plugins test cases.
    """
    def test_plugin_families(self):
        self.assertTrue(self.server.load_plugin_families())

    def test_plugin_rules(self):
        self.assertTrue(self.server.load_plugin_rules())

    def test_create_plugin_rule(self):
        plugin_rule = self.server.PluginRule()
        plugin_rule.plugin_id = 0
        plugin_rule.type = Severity.RECAST_CRITICAL
        plugin_rule.date = None
        plugin_rule.host = "localhost"
        self.assertTrue(plugin_rule.create())

    def test_edit_plugin_rule(self):
        self.assertTrue(self.server.load_plugin_rules())
        for plugin_rule in self.server.plugin_rules:
            plugin_rule.type = Severity.RECAST_INFO
            self.assertTrue(plugin_rule.edit())

    def test_delete_plugin_rule(self):
        self.assertTrue(self.server.load_plugin_rules())
        for plugin_rule in self.server.plugin_rules:
            self.assertTrue(plugin_rule.delete())


class PolicyTestCase(NessusTestCase):
    """
    Nessus policies test cases.
    """

    def test_load_policies(self):
        self.assertTrue(self.server.load_policies())

    def test_create_policy(self):
        self.assertTrue(self.server.load_templates())
        policy = self.server.Policy()
        policy.name = random_name(8)
        policy.template_uuid = self.server.templates[0].uuid
        self.assertTrue(policy.create())

    def test_edit_policy(self):
        self.assertTrue(self.server.load_policies())
        for policy in self.server.policies:
            policy.name = random_name(10)
            self.assertTrue(policy.edit())

    def test_z_delete_policies(self):
        self.assertTrue(self.server.load_policies())
        for policy in self.server.policies:
            self.assertTrue(policy.delete())

    def test_details_policy(self):
        self.assertTrue(self.server.load_policies())
        for policy in self.server.policies:
            self.assertTrue(policy.details())

    def test_copy_policy(self):
        self.assertTrue(self.server.load_policies())
        for policy in self.server.policies:
            self.assertIsInstance(policy.copy(), Policy)

    def test_export_policy(self):
        self.assertTrue(self.server.load_policies())
        for policy in self.server.policies:
            filename = "/tmp/%s.nessus" % random_name(8)
            self.assertEqual(filename, policy.export(filename))

    #def test_import_policy(self):
    #    filename = "BK0NIHOQ.nessus"
    #    self.assertTrue(self.server.import_policy(filename))


class ProxyTestCase(NessusTestCase):
    """
    Nessus proxy settings test cases.
    """

    def test_view(self):
        """
        Tests Nessus proxy settings view.
        :return:
        """
        self.assertTrue(self.server.load_proxy())
        self.assertIsNotNone(self.server.proxy.proxy)
        self.assertIsNotNone(self.server.proxy.proxy_port)
        self.assertIsNotNone(self.server.proxy.proxy_username)
        self.assertIsNotNone(self.server.proxy.proxy_password)
        self.assertIsNotNone(self.server.proxy.user_agent)

    def test_change(self):
        """
        Tests Nessus proxy settings update.
        :return:
        """
        self.assertTrue(self.server.load_proxy())

        self.server.proxy.proxy = "localhost"
        self.server.proxy.proxy_port = 8080
        self.server.proxy.proxy_username = "test"
        self.server.proxy.proxy_password = "test"
        self.server.proxy.user_agent = "test"

        self.assertTrue(self.server.proxy.update())

        self.assertTrue(self.server.load_proxy())

        self.assertEqual(self.server.proxy.proxy, "localhost")
        self.assertEqual(self.server.proxy.proxy_port, 8080)
        self.assertEqual(self.server.proxy.proxy_username, "test")
        self.assertEqual(self.server.proxy.proxy_password, "********")
        self.assertEqual(self.server.proxy.user_agent, "test")


class ScannerTestCase(NessusTestCase):
    """
    Nessus scanners test cases.
    """

    def test_list(self):
        """
        Tests Nessus scanners listing.
        :return:
        """
        self.assertTrue(self.server.load_scanners())
        self.assertGreater(len(self.server.scanners), 0)


class ScanTestCase(NessusTestCase):
    """
    Nessus scans test cases.
    """

    def test_configure(self):
        self.assertTrue(self.server.load_scans())
        for scan in self.server.scans:
            scan.name = random_name(8)
            self.assertTrue(scan.configure())

    def test_copy(self):
        self.assertTrue(self.server.load_scans())
        for scan in self.server.scans:
            self.assertIsInstance(scan.copy(), Scan)

    def test_create(self):
        scan = self.server.Scan()
        scan.template = self.server.templates[0]
        scan.name = random_name(8)
        scan.description = "Testing scan"
        scan.scanner = self.server.scanners[0]
        scan.tag = self.server.folders[0]
        scan.custom_targets = "127.0.0.1"
        self.assertTrue(scan.create())
        self.assertTrue(scan.stop())

    def test_z_delete(self):
        self.assertTrue(self.server.load_scans())
        for scan in self.server.scans:
            if "Copy" in scan.name:
                self.assertTrue(scan.delete())

    def test_delete_history(self):
        self.assertTrue(self.server.load_scans())
        for scan in self.server.scans:
            self.assertTrue(scan.details())
            for history in scan.history:
                self.assertTrue(scan.delete_history(history.history_id))

    def test_details(self):
        self.assertTrue(self.server.load_scans())
        for scan in self.server.scans:
            self.assertTrue(scan.details())

    def test_download(self):
        self.assertTrue(self.server.load_scans())
        if len(self.server.scans):
            for fmt in FORMATS:
                filename = "/tmp/%s.%s" % (random_name(8), fmt)
                self.assertEqual(filename, self.server.scans[0].download(filename, fmt, password="S0l33t"))

    def test_host_details(self):
        return

    def test_import(self):
        # self.assertTrue(self.server.import_scan("A59VVNKO_xxtzj9.nessus"))
        return

    def test_launch_pause_resume_stop(self):
        scan = self.server.Scan()
        scan.template = self.server.templates[0]
        scan.name = random_name(8)
        scan.description = "Testing scan"
        scan.scanner = self.server.scanners[0]
        scan.tag = self.server.folders[0]
        scan.custom_targets = "127.0.0.1"
        self.assertTrue(scan.launch())
        sleep(10)
        self.assertTrue(scan.pause())
        sleep(10)
        self.assertTrue(scan.resume())
        sleep(10)
        self.assertTrue(scan.stop())

    def test_list(self):
        self.assertTrue(self.server.load_scans())

    def test_schedule(self):
        return

    def test_timezones(self):
        return


class ServerTestCase(NessusTestCase):
    """
    Nessus servers test cases.
    """

    def test_properties(self):
        """
        Tests Nessus server properties.
        :return:
        """
        self.assertTrue(self.server.load_properties())


class SessionTestCase(NessusTestCase):
    """
    Nessus sessions test cases.
    """


class UserTestCase(NessusTestCase):
    """
    Nessus users test cases.
    """

    def test_create(self):
        """
        Tests Nessus user creation.
        :return:
        """
        user = self.server.User()
        user.username = user.username = random_name(8)
        user.password = "P@ssw0rd"
        self.assertTrue(user.create())

    def test_edit(self):
        """
        Tests Nessus user edition.
        :return:
        """
        user = self.server.User()
        user.username = user.username = random_name(8)
        user.password = "P@ssw0rd"
        self.assertTrue(user.create())
        user.name = random_name(8)
        self.assertTrue(user.edit())

    def test_delete(self):
        """
        Tests Nessus user deletion.
        :return:
        """
        # Delete everyone except our test user.
        self.assertTrue(self.server.load_users())
        for user in [u for u in self.server.users if u.username != self.server.user.username]:
            self.assertTrue(user.delete())