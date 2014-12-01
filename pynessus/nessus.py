"""
Copyright 2014 Quentin Kaiser

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.

You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from httplib import HTTPSConnection, CannotSendRequest, ImproperConnectionState, HTTPException
import hashlib
import base64
from random import randint
import os
import json
from xml.dom.minidom import parseString
from time import sleep

from models.scan import Scan, Vulnerability, Note, Host, Remediation
from models.schedule import Schedule
from models.tag import Tag
from models.policy import Policy, Plugin, PluginFamily, PreferenceValue, Preference
from models.user import User
from models.report import Report


class NessusAPIError(Exception):
    pass


class Nessus(object):
    """
        A Nessus Server instance.
    """

    def __init__(self, url="", port=8834):
        """
        Constructor.
        Params:
            url(string): nessus server's url
            port(int): nessus server's port
        Returns:
        """
        self._url = url
        self._port = port

        self._uuid = 0
        self._connection = None
        self._product = None
        self._engine = None
        self._web_ui = None
        self._misc_settings = []
        self._loaded_plugin_set = None
        self._scanner_boottime = 0
        self._idle_timeout = 0
        self._plugin_set = None
        self._plugins_lastupdated = 0
        self._plugins_expiration = 0

        self._web_server_version = None
        self._expiration = None
        self._nessus_ui_version = None
        self._ec2 = None
        self._nessus_type = None
        self._capabilities = None
        self._plugin_set = None
        self._idle_timeout = None
        self._scanner_boottime = None
        self._server_version = None
        self._feed = None

        #managing multiple user sessions
        self._user = None

        self._schedules = []
        self._policies = []
        self._scans = []
        self._tags = []
        self._users = []
        self._notifications = []
        self._reports = []

        self._headers = {
            "Content-type": "application/json",
            "Accept": "application/json",
            "Cookie": 'csrftoken="%s";nessus-session="null";sessionid="%s";token="";' % (hashlib.md5("pynessus").hexdigest(),
                                                                                hashlib.md5("pynessus_").hexdigest())}

    def Scan(self):
        return Scan(self)

    def Host(self):
        return Host(self)

    def Policy(self):
        return Policy(self)

    def Schedule(self):
        return Schedule(self)

    def User(self, username=None, password=None):
        return User(self, username, password)

    def Tag(self):
        return Tag(self)

    def Report(self):
        return Report(self)

    def _request(self, method, target, params, headers=None):
        """
        Send an HTTP request.
        Params:
            method(string): HTTP method (i.e. GET, POST, PUT, DELETE, HEAD)
            target(string): target path (i.e. /schedule/new)
            params(string): HTTP parameters
            headers(array): HTTP headers
        Returns:
            Response body if successful, None otherwise.
        """
        try:
            if self._connection is None:
                self._connection = HTTPSConnection(self._url, self._port)
            self._connection.request(method, target, params, self._headers if headers is None else headers)
        except CannotSendRequest:
            self._connection = HTTPSConnection(self._url, self._port)
            self.login(self._user)
            self._request(method, target, params, self._headers)
        except ImproperConnectionState:
            self._connection = HTTPSConnection(self._url, self._port)
            self.login(self._user)
            self._request(method, target, params, self._headers)
        response = self._connection.getresponse()

        return response.read()

    def _api_request(self, method, target, params=None):
        """
        Send a request to the Nessus REST API.
        Params:
            method(string): HTTP method (i.e. GET, PUT, POST, DELETE, HEAD)
            target(string): target path (i.e. /schedule/new)
            params(dict): HTTP parameters
        Returns:
            dict: parsed dict from json answer, None if no content.
        """
        if not params:
            params = {}
        params['json'] = 1
        for _ in range(3):
            response = json.loads(self._request(method, target, json.dumps(params)))
            if not "error" in response:
                break

        if "error" in response:
            raise NessusAPIError(response["error"])
        elif response['reply']['status'] == "OK":
            return response["reply"]["contents"]
        else:
            return None

    @staticmethod
    def _encode(filename):
        """
        Encode filename content into a multipart/form-data data string.
        Params:
            filename(string): filename of the file that will be encoded.
        Returns:
            string: multipart/form-data data string
        """

        boundary = '----------bundary------'
        crlf = '\r\n'
        body = []

        with open(filename, "rb") as f:
            body.extend(
                [
                    '--' + boundary,
                    'Content-Disposition: form-data; name="Filedata"; filename="%s"' % (os.path.basename(filename)),
                    'Content-Type: text/xml',
                    '',
                    f.read(),
                ]
            )
            body.extend(['--' + boundary + '--', ''])
        return 'multipart/form-data; boundary=%s' % boundary, crlf.join(body)

    def login(self, user):
        """
        Log into Nessus server with provided user profile.
        Args:
            user (User): user instance
        Returns:
            bool: True if successful login, False otherwise.
        Raises:
        """
        params = {'login': user.username, 'password': user.password}
        response = self._api_request("POST", "/login", params)
        if response is not None:
            self._user = user
            self._user.token = response['token']
            self._user.admin = True if response['user']['admin'] == "TRUE" else False
            self._scanner_boottime = response['scanner_boottime']
            self._idle_timeout = response['idle_timeout']
            self._plugin_set = response['plugin_set']
            self._loaded_plugin_set = response["loaded_plugin_set"]
            self._uuid = response['server_uuid']
            # Persist token value for subsequent requests
            self._headers["Cookie"] = "token=%s" % (response['token'])
            return True
        else:
            return False

    def logout(self):
        """
        Log out of the Nessus server, invalidating the current token value.
        Returns:
            bool: True if successful login, False otherwise.
        """

        response = self._api_request("POST", "/logout")
        if response == "OK":
            return True
        else:
            return False


    def load(self):
        """
        Glue function to load all data from the server.
        Returns:
        """
        self.load_properties()
        self.load_users()
        self.load_tags()
        self.load_policies()
        self.load_scans()
        self.load_reports()

    def load_properties(self):
        """
        Log Nessus server properties.
        Returns:
            bool: True if successful login, False otherwise.
        """
        response = self._api_request("GET", "/server/properties?json=1", {})
        if response is not None:
            self._loaded_plugin_set = response["loaded_plugin_set"]
            self._uuid = response["server_uuid"]
            self._expiration = response["expiration"]
            self._nessus_ui_version = response["nessus_ui_version"]
            self._nessus_type = response["nessus_type"]
            self._notifications = []
            for notification in response["notifications"]:
                self._notifications.append(notification)
            self._capabilities = response["capabilities"]
            self._plugin_set = response["plugin_set"]
            self._idle_timeout = response["idle_timeout"]
            self._scanner_boottime = response["scanner_boottime"]
            self._server_version = response["server_version"]
            self._feed = response["feed"]
            return True
        else:
            return False

    def load_scans(self, tag_id=None):
        """
        Load Nessus server's scans. Load scans from a specific tag if tag_id is provided.
        Params:
            tag_id(int, optional): Tag's identification number.
        Returns:
            bool: True if successful login, False otherwise.
        """
        params = {}
        if tag_id is not None:
            params['tag_id'] = tag_id
        response = self._api_request("POST", "/result/list", params)
        if response is not None:
            if "result" in response:
                self._scans = []
                for result in response['result']:
                    scan = self.Scan()
                    scan.status = result["status"]
                    scan.name = result["name"]
                    scan.tag = result["tags"]
                    scan.read = result["read"]
                    scan.timestamp = result["timestamp"]
                    scan.last_modification_date = result["last_modification_date"]
                    scan.object_id = result["object_id"]
                    scan.creation_date = result["creation_date"]
                    scan.user_permissions = result["user_permissions"]
                    scan.owner = result["owner"]
                    scan.shared = result["shared"]
                    scan.type = result["type"]
                    scan.id = result["id"]
                    for user in self.users:
                        if user.id == result["owner_id"]:
                            scan.owner = user
                    self._scans.append(scan)
            return True
        else:
            return False

    def load_tags(self):
        """
        Load Nessus server's tags.
        Params:

        Returns:
            bool: True if successful login, False otherwise.
        """
        response = self._api_request("POST", "/tag/list")
        if response is not None:
            self._tags = []
            for result in response['tags']:
                tag = self.Tag()
                tag.id = result["id"]
                tag.type = result["type"] if "type" in result else "local"
                tag.custom = result["custom"]
                tag.default_tag = result["default_tag"]
                tag.name = result["name"]
                tag.unread_count = result["unread_count"] if "unread_count" in result else 0
                self._tags.append(tag)
            return True
        else:
            return False

    def load_policies(self):
        """
        Load Nessus server's policies.
        Params:
        Returns:
            bool: True if successful login, False otherwise.
        """
        response = self._api_request("POST", "/policy/list/policies")
        if response is not None:
            if "policy" in response["policies"]:
                self._policies = []
                for result in response['policies']["policy"]:
                    policy = self.Policy()
                    policy.id = result["id"]
                    policy.db_id = result["db_id"]
                    policy.name = result["name"]
                    policy.owner = result["owner"]
                    policy.creation_date = result["creation_date"]
                    policy.no_target = result["no_target"] if "no_target" in result else False
                    policy.visibility = result["visibility"]
                    policy.shared = result["shared"]
                    policy.user_permissions = result["user_permissions"]
                    policy.timestamp = result["timestamp"]
                    policy.last_modification_date = result["last_modification_date"]
                    policy.creation_date = result["creation_date"]
                    policy.object_id = result["object_id"]
                    self._policies.append(policy)
            return True
        else:
            return False


    def load_users(self):
        """
        Load Nessus server's users.
        Params:
        Returns:
            bool: True if successful login, False otherwise.
        """
        response = self._api_request("POST", "/user/list")
        if response is not None:
            self._users = []
            for result in response["user"]:
                user = self.User()
                user.last_login = result["lastlogin"]
                user.permissions = result["permissions"]
                user.type = result["type"]
                user.name = result["name"]
                user.username = result["username"]
                user.id = result["id"]
                self._users.append(user)
            return True
        else:
            return False


    def load_reports(self):
        """
        Load Nessus server's reports.
        Params:
        Returns:
            bool: True if successful login, False otherwise.
        """
        response = self._api_request("POST", "/report/list")
        if response is not None:
            if "report" in response["reports"]:
                self._reports = []
                for result in response["reports"]["report"]:
                    r = self.Report()
                    r.id = result["name"]
                    r.name = result["name"]
                    r.readable_name = result["readableName"]
                    r.status = result["status"]
                    r.timestamp = result["timestamp"]
                    self._reports.append(r)
            return True
        else:
            return False

    def create_user(self, user):
        """
        Create a new user.
        Params:
            user(User): a user instance that will be created.
        Returns:
            bool: True if successful, False otherwise.
        """
        params = {
            "login": user.username,
            "permissions": user.permissions,
            "type": user.type,
            "password": user.password
        }
        response = self._api_request("POST", "/user/add", params)
        if response is not None:
            user.name = response["name"]
            user.permissions = response["permissions"]
            user.id = response["id"]
            return True
        else:
            return False

    def update_user(self, user):
        """
        Update a user.
        Params:
            user(User): a user instance that will be updated.
        Returns:
            bool: True if successful, False otherwise.
        """
        params = {
            "user_id": user.id,
            "login": user.username,
            "permissions": user.permissions,
            "type": user.type,
            "password": user.password
        }
        response = self._api_request("POST", "/user/edit", params)
        if response is not None:
            user.name = response["name"]
            user.permissions = response["permissions"]
            user.id = response["id"]
            return True
        else:
            return False

    def delete_user(self, user):
        """
        Delete a user.
        Params:
            user(User): a user instance that will be deleted.
        Returns:
            bool: True if successful, False otherwise.
        """
        params = {
            "user_id": user.id
        }
        response = self._api_request("POST", "/user/delete", params)
        if response is not None:
            return True
        else:
            return False

    def create_scan(self, scan):
        """
        Create and launch a new scan.
        Params:
            scan(Scan): a scan instance that will be launched.
        Returns:
            bool: True if successful, False otherwise.
        """
        params = {
            'policy_id': scan.policy.object_id,
            'name': scan.name,
            'tag_id': scan.tag.id,
            'custom_targets': scan.custom_targets
        }
        if scan.target_file_name is not None:
            params['target_file_name'] = scan.target_file_name

        response = self._api_request("POST", "/scan/new", params)
        if response is not None:
            scan.id = response["scan"]["id"]
            scan.uuid = response["scan"]["uuid"]
            scan.status = response["scan"]["status"]
            scan.start_time = response["scan"]["start_time"]
            for user in self.users:
                if user.name == response["scan"]["owner"]:
                    scan.owner = user
            return True
        else:
            return False

    def pause_scan(self, scan):
        """
        Pause a running scan.
        Params:
            scan(Scan): a scan instance that will be paused.
        Returns:
            bool: True if successful, False otherwise.
        """
        params = {
            'scan_uuid': scan.uuid
        }
        response = self._api_request("POST", "/scan/pause", params)
        if response is not None:
            return True
        else:
            return False

    def resume_scan(self, scan):
        """
        Resume a paused scan.
        Params:
            scan(Scan): a scan instance that will be resumed.
        Returns:
            bool: True if successful, False otherwise.
        """
        params = {
            'scan_uuid': scan.uuid
        }
        response = self._api_request("POST", "/scan/resume", params)
        if response is not None:
            return True
        else:
            return False

    def stop_scan(self, scan):
        """
        Stop a running scan.
        Params:
            scan(Scan): a scan instance that will be stopped.
        Returns:
            bool: True if successful, False otherwise.
        """
        params = {
            'scan_uuid': scan.uuid
        }
        response = self._api_request("POST", "/scan/stop", params)
        if response is not None:
            return True
        else:
            return False

    def move_scan(self, scan, tag):
        """
        Move a scan from a tag to another.
        Params:
            scan(Scan): A scan instance.
            tag(Tag): The tag where the scan will be placed.
        Returns:
            bool: True if successful, False otherwise.
        """
        params = {
            'id': scan.uuid,
            'tags': tag.id
        }
        response = self._api_request("POST", "/tag/replace", params)
        if response is not None:
            return True
        else:
            return False

    def delete_scan(self, scan):
        """
        Delete a scan.
        Params:
            scan(Scan): a scan instance that will be stopped.
        Returns:
            bool: True if successful, False otherwise.
        """
        params = {
            'id': scan.uuid
        }
        response = self._api_request("POST", "/result/delete", params)
        if response is not None:
            return True
        else:
            return False

    def set_scan_status(self, scan, status="read"):
        """
        Modify the scan status (read, unread).
        Params:
            scan(Scan): scan instance
            status(string): scan status (i.e. read, unread)
        Returns:
            bool: True if successful, False otherwise.
        """
        params = {
            'id': scan.uuid,
            'status': status
        }
        response = self._api_request("POST", "/result/status/set", params)
        if response is not None:
            return True
        else:
            return False

    def load_scan_diff(self, scan1, scan2):
        """
        Create a diff report between scan1 and scan2.
        Params:
            scan1(Scan): first scan instance
            scan2(Scan): second scan instance
        Returns:
            bool: True if successful, False otherwise.
        """
        params = {
            'report1': scan1.id,
            'report2': scan2.id
        }
        response = self._api_request("POST", "/result/diff", params)
        if response is not None:
            scan = self.Scan()
            scan.uuid = response["report"]
            params = {
                "id": scan.uuid,
                "status": "read"
            }
            response = self._api_request("POST", "/result/status/set", params)
            if response is not None:
                return scan
            else:
                return None
        else:
            return None

    def load_scan_vulnerabilities(self, scan):
        """
        Load vulnerabilities results from scan.
        Params:
            scan(Scan): scan that we will load.
        Returns:
            True if successful, False otherwise.
        """
        params = {
            'id': scan.id
        }
        response = self._api_request("POST", "/result/details", params)
        if response is not None:
            scan._vulnerabilities = []
            for vulnerability in response["vulnerabilities"]:
                v = Vulnerability()
                v.plugin_id = vulnerability["plugin_id"]
                v.plugin_name = vulnerability["plugin_name"]
                v.plugin_family = vulnerability["plugin_family"]
                v.severity = vulnerability["severity"]
                v.severity_index = vulnerability["severity_index"]
                v.count = vulnerability["count"]
                v.vuln_index = vulnerability["vuln_index"]
                #scan.vulnerabilities.append(v)
            return True
        else:
            return False

    def load_scan_remediations(self, scan):
        """
        Load a scan remediations content.
        :param scan:
        :return:
        """
        params = {
            'id': scan.id
        }
        response = self._api_request("POST", "/result/details", params)
        if response is not None:
            scan._remediations = []
            if "remediations" in response["remediations"]:
                for remediation in response["remediations"]["remediations"]:
                    r = Remediation()
                    r.text = remediation["remediation"]
                    r.value = remediation["value"]
                    r.vulns = remediation["vulns"]
                    r.hosts = remediation["hosts"]
                    scan.remediations.append(r)
            return True
        else:
            return False

    def load_scan_notes(self, scan):
        """
        Load a scan notes.
        Params:
            scan(Scan):
        Returns:
        """
        params = {
            'id': scan.id
        }
        response = self._api_request("POST", "/result/details", params)
        if response is not None:
            scan.notes = []
            if "note" in response["notes"]:
                for note in response["notes"]["note"]:
                    n = Note()
                    n.title = note["title"]
                    n.message = note["message"]
                    n.severity = note["severity"]
                    scan.notes.append(n)
            return True
        else:
            return

    def load_scan_hosts(self, scan):
        """
        Load a scan notes.
        Params:
            scan(Scan):
        Returns:
        """
        params = {
            'id': scan.id
        }
        response = self._api_request("POST", "/result/details", params)
        if response is not None:
            scan.hosts = []
            for host in response["hosts"]:
                    h = self.Host()
                    h.scan = scan
                    h.host_index = host["host_index"]
                    h.totalchecksconsidered = host["totalchecksconsidered"]
                    h.numchecksconsidered = host["numchecksconsidered"]
                    h.scanprogresstotal = host["scanprogresstotal"]
                    h.scanprogresscurrent = host["scanprogresscurrent"]
                    h.score = host["score"]
                    h.progress = host["progress"]
                    h.critical = host["critical"]
                    h.high = host["high"]
                    h.medium = host["medium"]
                    h.low = host["low"]
                    h.info = host["info"]
                    h.severity = host["severity"]
                    h.host_id = host["host_id"]
                    h.hostname = host["hostname"]
                    scan.hosts.append(h)
            return True
        else:
            return False

    def load_host_info(self, host):
        """

        :param host:
        :return:
        """
        params = {
            'id': host.scan.id,
            'host_id': host.id
        }
        response = self._api_request("POST", "/result/details", params)
        if response is not None:
            host.vulnerabilities = []
            for vulnerability in response["vulnerabilities"]:
                    v = Vulnerability()
                    v.plugin_id = vulnerability["plugin_id"]
                    v.plugin_name = vulnerability["plugin_name"]
                    v.plugin_family = vulnerability["plugin_family"]
                    v.severity = vulnerability["severity"]
                    v.severity_index = vulnerability["severity_index"]
                    v.count = vulnerability["count"]
                    v.vuln_index = vulnerability["vuln_index"]
                    host.vulnerabilities.append(v)
            return True
        else:
            return False

    def load_host_vulnerabilities(self, host):
        params = {
            'id': host.scan.id,
            'host_id': host.id
        }
        response = self._api_request("POST", "/result/details", params)
        if response is not None:
            host.vulnerabilities = []
            for vulnerability in response["vulnerabilities"]:
                    v = Vulnerability()
                    v.plugin_id = vulnerability["plugin_id"]
                    v.plugin_name = vulnerability["plugin_name"]
                    v.plugin_family = vulnerability["plugin_family"]
                    v.severity = vulnerability["severity"]
                    v.severity_index = vulnerability["severity_index"]
                    v.count = vulnerability["count"]
                    v.vuln_index = vulnerability["vuln_index"]
                    host.vulnerabilities.append(v)
            return True
        else:
            return False

    def load_host_compliance(self, host):
        """

        :param host:
        :return:
        """
        raise Exception("Not yet implemented.")

    def upload_file(self, filename):
        """
        Upload the file identified by filename to the server.
        Params:
            filename(string): file path
        Returns:
            bool: True if successful, False otherwise.
        """
        if not os.path.isfile(filename):
            raise Exception("This file does not exist.")
        else:
            content_type, body = self._encode(filename)
            headers = dict()
            headers["Content-type"] = content_type
            headers["Accept"] = "application/json"
            headers["Cookie"] = self._headers["Cookie"]
            response = self._request("POST", "/file/upload", body, headers)
            root = parseString(response.replace("\n", ""))

            if root.getElementsByTagName("reply")[0].getElementsByTagName("status")[0].firstChild.data == "OK":
                return True
            else:
                return False

    def create_policy(self, policy):
        """
        Create a new policy.
        Params:
            policy(Policy): policy instance to be created.
        Returns:
            bool: True if successful, False otherwise.
        """
        params = {
            "policy_id": 0,
            "general.Basic.0": policy.name,
            "general.Basic.1": policy.description
        }
        if policy.settings is not None:
            params = dict(params.items() + policy.settings.items())
        response = self._api_request("POST", "/policy/update", params)
        if response is not None:
            policy.id = response["metadata"]["id"]
            for user in self.users:
                if user.name == response["metadata"]["owner"]:
                    policy.owner = user
            policy.visibility = response["metadata"]["visibility"]
            self.load_policies()
            return True
        else:
            return False

    def update_policy(self, policy):
        """
        Update a policy.
        Params:
            policy(Policy): policy instance to be created.
        Returns:
            bool: True if successful, False otherwise.
        """
        params = {
            "policy_id": policy.id,
            "general.Basic.0": policy.name,
            "general.Basic.1": policy.description
        }
        if policy.settings is not None:
            for k in policy.settings:
                params[k] = policy.settings[k]
        response = self._api_request("POST", "/policy/update", params)
        if response is not None:
            policy.id = response["metadata"]["id"]
            for user in self.users:
                if user.name == response["metadata"]["owner"]:
                    policy.owner = user
            policy.visibility = response["metadata"]["visibility"]
            self.load_policies()
            for _p in self.policies:
                if int(_p.id) == int(policy.id):
                    policy.db_id = _p.db_id
                    policy.object_id = _p.object_id
            return True
        else:
            return False

    def clone_policy(self, policy):
        """
        Clone a policy.
        Params:
            policy(Policy): policy instance to be created.
        Returns:
            Policy: the policy copy.
        """
        params = {"policy_id": policy.id}
        response = self._api_request("POST", "/policy/copy", params)
        if response is not None:
            _p = response["policy"]
            p = self.Policy()
            p.name = _p["policyname"]
            if "policycomments" in _p["policycontents"]:
                p.description = _p["policycontents"]["policycomments"]
            for user in self.users:
                if user.name == _p["policyowner"]:
                    policy.owner = user
            p.id = _p["policyid"]
            p.visibility = _p["visibility"]
            self.load_policies()
            for _p in self.policies:
                if int(_p.id) == int(p.id):
                    p.db_id = _p.db_id
                    p.object_id = _p.object_id
            return p
        else:
            raise None

    def delete_policy(self, policy):
        """
        Delete a policy.
        Params:
            policy(Policy): policy instance to be created.
        Returns:
            bool: True if successful, False otherwise.
        """
        params = {
            "policy_id": policy.id
        }
        response = self._api_request("POST", "/policy/delete", params)
        if response is not None:
            return True
        else:
            return False

    def download_policy(self, policy, filename=None):
        """
        Download a policy description file.
        Params:
            policy(Policy): policy to be downloaded
        Returns:
            string: path where the policy has been saved.
        """
        if filename is None:
            filename = "nessus_policy_%s.nessus" % policy.name
        try:
            response = self._request("GET", "/policy/download?policy_id=%d" % policy.id, "")
            with open(filename, "wb") as f:
                f.write(response)
            return filename
        except HTTPException as e:
            return None

    def load_policy_preferences(self, policy):
        """
        Load and assign policy preferences
        Params:
            policy(Policy): policy instance
        Returns:
        """
        params = {
            "policy_id": policy.id
        }
        response = self._api_request("POST", "/policy/list/plugins/preferences", params)
        if response is not None:
            policy.preferences = []
            if "preference" in response["pluginpreferences"]:
                for preference in response["pluginpreferences"]["preference"]:
                    p = Preference()
                    p.name = preference["name"]
                    for value in preference["values"]:
                        v = PreferenceValue()
                        v.type = value["type"]
                        v.name = value["name"]
                        v.id = value["id"]
                        p.values.append(v)
                    policy.preferences.append(p)
            return True
        else:
            return False

    def load_policy_plugins(self, policy):
        """

        :param policy:
        :return:
        """

        params = {
            "policy_id": policy.id
        }
        response = self._api_request("POST", "/policy/list/families", params)
        if response is not None:
            if "family" in response["policyfamilies"]:
                families = []
                for family in response["policyfamilies"]["family"]:
                    pf = PluginFamily()
                    pf.name = family["name"]
                    pf.id = family["id"]
                    pf.plugin_count = family["plugin_count"]
                    pf.status = family["status"]
                    params2 = {
                        "policy_id": policy.id,
                        "family_id": pf.id
                    }
                    response2 = self._api_request("POST", "/policy/list/plugins", params2)
                    if response2 is not None:
                        for plugin in response2["policyplugins"]["plugin"]:
                            p = Plugin()
                            p.name = plugin["pluginname"]
                            p.filename = plugin["pluginfilename"]
                            p.id = plugin["pluginid"]
                            p.status = plugin["status"]
                            pf.plugins.append(p)
                    families.append(pf)
                policy.plugins = families
            return True
        else:
            return False

    def create_tag(self, tag):
        """
        Create a new tag.
        Params:
            tag(Tag): tag instance to be created.
        Returns:
            bool: True if successful, False otherwise.
        """
        params = {
            "name": tag.name
        }
        response = self._api_request("POST", "/tag/create", params)
        if response is not None:
            tag.id = response["id"]
            return True
        else:
            return False

    def update_tag(self, tag):
        """
        Update a tag.
        Params:
            tag(Tag): tag instance to be updated.
        Returns:
            bool: True if successful, False otherwise.
        """
        params = {
            "tag_id": tag.id,
            "name": tag.name
        }
        response = self._api_request("POST", "/tag/edit", params)
        if response is not None:
            return True
        else:
            return False

    def delete_tag(self, tag):
        """
        Delete a tag.
        Params:
            tag(Tag): tag instance to be deleted.
        Returns:
            bool: True if successful, False otherwise.
        """
        params = {
            "tag_id": tag.id
        }
        response = self._api_request("POST", "/tag/delete", params)
        if response is not None:
            return True
        else:
            return False

    def launch_schedule(self, schedule):
        """
        Launch a schedule.
        Params:
            schedule(Schedule): schedule instance to be launched.
        Returns:
            bool: True if successful, False otherwise.
        """
        params = {
            "schedule_id": schedule.id
        }
        response = self._api_request("POST", "/schedule/launch", params)
        if response is not None:
            return True
        else:
            return False

    def create_schedule(self, schedule):
        """
        Create a schedule.
        Params:
            schedule(Schedule): schedule instance to be created.
        Returns:
            bool: True if successful, False otherwise.
        """
        params = {
            "name": schedule.name,
            "description": schedule.description,
            "tag_id": schedule.tag.id,
            "rrules": schedule.rrules,
            "starttime": schedule.starttime,
            "timezone": schedule.timezone,
            "custom_targets": schedule.custom_targets,
            "emails": schedule.emails,
            "notification_filter_type": schedule.notification_filter_type,
            "notification_filters": schedule.notification_filters,
            "policy_id": schedule.policy.object_id
        }
        response = self._api_request("POST", "/schedule/new", params)
        if response is not None:
            template = response["template"]
            schedule.uuid = template["uuid"]
            schedule.name = template["name"]
            schedule.description = template["description"]
            schedule.scanner = template["scanner_id"]
            schedule.emails = template["emails"]
            schedule.custom_targets = template["custom_targets"]
            schedule.starttime = template["starttime"]
            schedule.rrules = template["rrules"]
            schedule.timezone = template["timezone"]
            schedule.notification_filter_type = template["notification_filter_type"]
            schedule.shared = template["shared"]
            schedule.user_permissions = template["user_permissions"]
            schedule.default_permissions = template["default_permisssions"]
            schedule.last_modification_date = template["last_modification_date"]
            schedule.creation_date = template["creation_date"]
            schedule.type = template["type"]
            schedule.id = template["id"]
            for tag in self.tags:
                if tag.id == template["tag_id"]:
                    schedule.tag = tag
            for user in self.users:
                if user.id == template["owner_id"]:
                    schedule.owner = user
            for policy in self.policies:
                if policy.id == template["policy_id"]:
                    schedule.policy = policy
            return True
        else:
            return False

    def update_schedule(self, schedule):
        """
        Update a schedule.
        Params:
            schedule(Schedule): schedule instance to be updated.
        Returns:
            bool: True if successful, False otherwise.
        """
        params = {
            "schedule_id": schedule.id,
            "name": schedule.name,
            "description": schedule.description,
            "tag_id": schedule.tag.id,
            "rrules": schedule.rrules,
            "starttime": schedule.starttime,
            "timezone": schedule.timezone,
            "custom_targets": schedule.custom_targets,
            "emails": schedule.emails,
            "notification_filter_type": schedule.notification_filter_type,
            "notification_filters": schedule.notification_filters,
            "policy_id": schedule.policy.object_id
        }
        response = self._api_request("POST", "/schedule/edit", params)
        if response is not None:
            template = response["template"]
            schedule.uuid = template["uuid"]
            schedule.name = template["name"]
            schedule.description = template["description"]
            schedule.scanner = template["scanner_id"]
            schedule.emails = template["emails"]
            schedule.custom_targets = template["custom_targets"]
            schedule.starttime = template["starttime"]
            schedule.rrules = template["rrules"]
            schedule.timezone = template["timezone"]
            schedule.notification_filter_type = template["notification_filter_type"]
            schedule.shared = template["shared"]
            schedule.user_permissions = template["user_permissions"]
            schedule.default_permissions = template["default_permisssions"]
            schedule.last_modification_date = template["last_modification_date"]
            schedule.creation_date = template["creation_date"]
            schedule.type = template["type"]
            schedule.id = template["id"]
            for tag in self.tags:
                if tag.id == template["tag_id"]:
                    schedule.tag = tag
            for user in self.users:
                if user.id == template["owner_id"]:
                    schedule.owner = user
            for policy in self.policies:
                if policy.id == template["policy_id"]:
                    schedule.policy = policy
            return True
        else:
            return False

    def delete_schedule(self, schedule):
        """
        Delete a schedule.
        Params:
            schedule(Schedule): schedule instance to be deleted.
        Returns:
            bool: True if successful, False otherwise.
        """
        params = {
            "schedule_id": schedule.id
        }

        response = self._api_request("POST", "/schedule/delete", params)
        if response is not None:
            return True
        else:
            return False

    def load_report(self, report, _format="nessus.v2"):
        """
        Download a report.
        Params:
            report(Report): report instance to be downloaded.
            format(string): report format (nessus.v2, html, csv, pdf, nessusdb)
        Returns:
            bool: True if successful, False otherwise.
        """
        response = self._api_request("POST", "/result/export", {"id": report.id, "format": _format})
        if response is not None:
            rid = response["file"]
            response = self._api_request("POST", "/result/export/status", {"rid": rid})
            while response is None or response["status"] != "ready":
                sleep(5)
                response = self._api_request("POST", "/result/export/status", {"rid": rid})
            response = self._request("GET", "/result/export/download?rid=%d" % rid, "")
            report.content = response
            report.format = _format
            return True
        else:
            return False

    def get_scan_progress(self, scan):
        """
        Get the scan progress (expressed in percentages).
        Params:
            scan(Scan):
        Returns:
        """
        params = {"id" : scan.uuid}
        response = self._api_request("POST", "/result/details", params)
        current = 0.0
        total = 0.0
        for host in response["hosts"]:
            current += host["scanprogresscurrent"]
            total += host["scanprogresstotal"]
        return current/(total if total else 1.0)*100.0

    def get_scan_status(self, scan):
        """
        Get the scan status (i.e. running, completed, paused, stopped)
        Params:
            scan(Scan):
        Returns:
            string: current scan status
        """
        params = {"id" : scan.uuid}
        response = self._api_request("POST", "/result/details", params)
        scan.status = response["info"]["status"]
        return response["info"]["status"]


    @property
    def scans(self):
        return self._scans

    @property
    def schedules(self):
        return self._schedules

    @property
    def policies(self):
        return self._policies

    @property
    def users(self):
        return self._users

    @property
    def tags(self):
        return self._tags

    @property
    def reports(self):
        return self._reports

    @policies.setter
    def policies(self, value):
        self._policies = value

    @scans.setter
    def scans(self, value):
        self._scans = value

    @schedules.setter
    def schedules(self, value):
        self._schedules = value

    @tags.setter
    def tags(self, value):
        self._tags = value

    @users.setter
    def users(self, value):
        self._users = value

    @reports.setter
    def reports(self, value):
        self._reports = value