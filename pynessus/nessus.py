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

from httplib import HTTPSConnection, CannotSendRequest, ImproperConnectionState
from random import randint
import os
import json
from xml.dom.minidom import parseString
from time import sleep

from models.scan import Scan
from models.schedule import Schedule
from models.tag import Tag
from models.policy import Policy
from models.plugin import Plugin, PluginFamily
from models.user import User
from models.folder import Folder
from models.template import Template
from models.host import Host


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

        # managing multiple user sessions
        self._user = None

        self._schedules = []
        self._policies = []
        self._templates = []
        self._scans = []
        self._tags = []
        self._folders = []
        self._users = []
        self._notifications = []
        self._reports = []

        self._headers = {
            "Content-type": "application/json",
            "Accept": "application/json"
        }

    def Scan(self):
        return Scan(self)

    def Host(self):
        return Host(self)

    def Policy(self):
        return Policy(self)

    def Plugin(self):
        return Plugin(self)

    def PluginFamily(self):
        return PluginFamily(self)

    def Schedule(self):
        return Schedule(self)

    def User(self, username=None, password=None):
        return User(self, username, password)

    def Tag(self):
        return Tag(self)

    def Folder(self):
        return Folder(self)

    def Template(self):
        return Template(self)

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
        params['seq'] = randint(0, 1000)
        params['json'] = 1
        response = json.loads(self._request(method, target, json.dumps(params)))
        if self.server_version[0] == "5":
            if "error" in response:
                raise NessusAPIError(response["error"])
            elif response['reply']['status'] == "OK":
                return response["reply"]["contents"]
            else:
                return None
        elif self.server_version[0] == "6":
            if response is not None and "error" in response:
                raise NessusAPIError(response["error"])
            return response
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
        if self.server_version[0] == "5":
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
        elif self.server_version[0] == "6":
            #TODO: add session creation and management
            params = {'username': user.username, 'password': user.password}
            response = self._api_request("POST", "/session", params)
            if response is not None:
                self._user = user
                self._user.token = response['token']
                # Persist token value for subsequent requests
                self._headers["X-Cookie"] = 'token=%s' % (response['token'])
                return True
            else:
                return False
        else:
            return False

    def logout(self):
        """
        Log out of the Nessus server, invalidating the current token value.
        Returns:
            bool: True if successful login, False otherwise.
        """
        if self.server_version[0] == "5":
            response = self._api_request("POST", "/logout")
            if response == "OK":
                return True
            else:
                return False
        else:
            self._api_request("DELETE", "/session")
            return True

    @property
    def status(self):
        """
        Return the Nessus server status.
        Params:
        Returns
        """
        if self.server_version[0] == "5":
            raise Exception("Not yet implemented.")
        elif self.server_version[0] == "6":
            response = self._api_request("GET", "/server/status", "")
            if response is not None:
                return response["status"]
            else:
                return "unknown"
        else:
            return "unknown"

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

    def load_templates(self):
        """
        Load Nessus server's scan templates.
        Params:
        Returns:
            bool: True if successful login, False otherwise.
        """
        if self.server_version[0] == "6":
            response = self._api_request("GET", "/editor/scan/templates", "")
            self._templates = []
            if "templates" in response:
                for t in response["templates"]:
                    template = self.Template()
                    template.uuid = t["uuid"]
                    template.title = t["title"]
                    template.name = t["name"]
                    template.description = t["desc"]
                    template.more_info = t["more_info"] if "more_info" in t else None
                    template.cloud_only = t["cloud_only"]
                    template.subscription_only = t["subscription_only"]
                    self._templates.append(template)
            return True
        else:
            raise Exception("Templates are not supported by Nessus version < 6.x .")

    def load_scans(self, tag_id=None):
        """
        Load Nessus server's scans. Load scans from a specific tag if tag_id is provided.
        Params:
            tag_id(int, optional): Tag's identification number.
        Returns:
            bool: True if successful login, False otherwise.
        """
        if self.server_version[0] == "5":
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
        elif self.server_version[0] == "6":
            response = self._api_request("GET", "/scans", "")
            self._scans = []
            if "scans" in response and response["scans"] is not None:
                for s in response["scans"]:
                    scan = self.Scan()
                    scan.status = s["status"]
                    scan.name = s["name"]
                    scan.read = s["read"]
                    scan.last_modification_date = s["last_modification_date"]
                    scan.creation_date = s["creation_date"]
                    scan.user_permissions = s["user_permissions"]
                    scan.shared = s["shared"]
                    scan.id = s["id"]
                    for user in self.users:
                        if user.id == s["owner_id"]:
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
        if self.server_version[0] == "5":
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
        else:
            return False

    def load_folders(self):
        """

        Params:
        Returns:
        """
        if self.server_version[0] == "6":
            response = self._api_request("GET", "/folders")
            if "folders" in response:
                self._folders = []
                for result in response["folders"]:
                    f = self.Folder()
                    f.id = result["id"]
                    f.type = result["type"] if "type" in result else "local"
                    f.custom = result["custom"]
                    f.default_tag = result["default_tag"]
                    f.name = result["name"]
                    f.unread_count = result["unread_count"] if "unread_count" in result else 0
                    self._folders.append(f)
                return True
            else:
                return False
        else:
            return False

    def load_policies(self):
        """
        Load Nessus server's policies.
        Params:
        Returns:
            bool: True if successful login, False otherwise.
        """
        if self.server_version[0] == "5":
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
        elif self.server_version[0] == "6":
            response = self._api_request("GET", "/policies")
            if "policies" in response:
                self._policies = []
                for result in response['policies']:
                    policy = self.Policy()
                    policy.id = result["id"]
                    policy.name = result["name"]
                    policy.owner = result["owner"]
                    policy.creation_date = result["creation_date"]
                    policy.no_target = result["no_target"] if "no_target" in result else False
                    policy.visibility = result["visibility"]
                    policy.shared = result["shared"]
                    policy.user_permissions = result["user_permissions"]
                    policy.last_modification_date = result["last_modification_date"]
                    policy.creation_date = result["creation_date"]
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
        if self.server_version[0] == "5":
            response = self._api_request("POST", "/user/list")
            if response is not None:
                users = []
                for result in response["user"]:
                    user = self.User()
                    user.last_login = result["lastlogin"]
                    user.permissions = result["permissions"]
                    user.type = result["type"]
                    user.name = result["name"]
                    user.username = result["username"]
                    user.id = result["id"]
                    users.append(user)
                return users
            else:
                return False
        elif self.server_version[0] == "6":
            response = self._api_request("GET", "/users")
            if "users" in response:
                users = []
                for result in response["users"]:
                    user = self.User()
                    user.last_login = result["lastlogin"]
                    user.permissions = result["permissions"]
                    user.type = result["type"]
                    user.name = result["name"]
                    user.username = result["username"]
                    user.id = result["id"]
                    users.append(user)
                return users
            else:
                return False
        else:
            return False

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
            if self.server_version[0] == 5:
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
            elif self.server_version[0] == "6":
                headers = self._headers
                headers["Content-type"] = content_type
                response = json.loads(self._request("POST", "/file/upload", body, self._headers))
                if "fileuploaded" in response and response["fileuploaded"] == os.path.basename(filename):
                    return True
                else:
                    return False
            else:
                return False

    #TODO : fix this shit!
    def load_report(self, report, _format="nessus.v2"):
        """
        Download a report.
        Params:
            report(Report): report instance to be downloaded.
            format(string): report format (nessus.v2, html, csv, pdf, nessusdb)
        Returns:
            bool: True if successful, False otherwise.
        """
        response = self._api_request("POST", "/result/export", {"id": report.name, "format": _format})
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

    @property
    def server_version(self):
        if self._server_version is None:
            if "404 File not found" not in self._request("GET", "/nessus6.html", ""):
                self.server_version = "6.x"
            elif self._request("GET", "/html5.html", "") is not None:
                self.server_version = "5.x"
            else:
                self.server_version = "unknown"
        return self._server_version

    @server_version.setter
    def server_version(self, value):
        self._server_version = value

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

    @property
    def templates(self):
        return self._templates

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

    @templates.setter
    def templates(self, value):
        self._templates = value