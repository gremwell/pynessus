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

from nessusobject import NessusObject

class Scan(NessusObject):
    """
    A Nessus Scan instance.

    Attributes:

    _Google Python Style Guide:
    http://google-styleguide.googlecode.com/svn/trunk/pyguide.html
    """

    def __init__(self, server):
        """Constructor"""
        super(Scan, self).__init__(server)
        self._id = 0
        self._status = None
        self._name = None
        self._description = None
        self._tag = None
        self._read = True
        self._timestamp = 0
        self._last_modification_date = 0
        self._object_id = -1
        self._creation_date = 0
        self._user_permissions = 0
        self._default_permissions = 0
        self._progress = 0
        self._owner = None
        self._shared = False
        self._type = None
        self._uuid = None
        self._policy = None
        self._template = None
        self._scanner = None
        self._custom_targets = None
        self._target_file_name = None
        self._vulnerabilities = None
        self._notes = None
        self._remediations = None
        self._hosts = None

    @property
    def status(self):
        return self._server.get_scan_status(self)

    @status.setter
    def status(self, status):
        self._status = status

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name):
        self._name = name

    @property
    def description(self):
        return self._description

    @description.setter
    def description(self, description):
        self._description = description

    @property
    def tag(self):
        return self._tag

    @tag.setter
    def tag(self, tag):
        self._tag = tag

    @property
    def read(self):
        return self._read

    @read.setter
    def read(self, read):
        self._read = read

    @property
    def timestamp(self):
        return self._timestamp

    @timestamp.setter
    def timestamp(self, timestamp):
        self._timestamp = timestamp

    @property
    def last_modification_date(self):
        return self._last_modification_date

    @last_modification_date.setter
    def last_modification_date(self, last_modification_date):
        self._last_modification_date = last_modification_date

    @property
    def object_id(self):
        return self._object_id

    @object_id.setter
    def object_id(self, object_id):
        self._object_id = object_id

    @property
    def creation_date(self):
        return self._creation_date

    @creation_date.setter
    def creation_date(self, creation_date):
        self._creation_date = creation_date

    @property
    def user_permissions(self):
        return self._user_permissions

    @user_permissions.setter
    def user_permissions(self, user_permissions):
        self._user_permissions = user_permissions

    @property
    def default_permissions(self):
        return self._default_permissions

    @default_permissions.setter
    def default_permissions(self, default_permissions):
        self._default_permissions = default_permissions

    @property
    def owner(self):
        return self._owner

    @owner.setter
    def owner(self, owner):
        self._owner = owner

    @property
    def shared(self):
        return self._shared

    @shared.setter
    def shared(self, shared):
        self._shared = shared

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, _type):
        self._type = _type

    @property
    def uuid(self):
        return self._uuid

    @uuid.setter
    def uuid(self, _uuid):
        self._uuid = _uuid

    @property
    def policy(self):
        return self._policy

    @policy.setter
    def policy(self, policy):
        self._policy = policy

    @property
    def template(self):
        return self._template

    @template.setter
    def template(self, template):
        self._template = template

    @property
    def scanner(self):
        return self._scanner

    @scanner.setter
    def scanner(self, scanner):
        self._scanner = scanner

    @property
    def custom_targets(self):
        return self._custom_targets

    @custom_targets.setter
    def custom_targets(self, custom_targets):
        self._custom_targets = custom_targets

    @property
    def target_file_name(self):
        return self._target_file_name

    @target_file_name.setter
    def target_file_name(self, target_file_name):
        self._target_file_name = target_file_name

    @property
    def vulnerabilities(self):
        if self._vulnerabilities is None:
            self._server.load_scan_vulnerabilities(self)
        return self._vulnerabilities

    @vulnerabilities.setter
    def vulnerabilities(self, value):
        self._vulnerabilities = value

    @property
    def notes(self):
        if self._notes is None:
            self._server.load_scan_notes(self)
        return self._notes

    @notes.setter
    def notes(self, value):
        self._notes = value

    @property
    def hosts(self):
        if self._hosts is None:
            self._server.load_scan_hosts(self)
        return self._hosts

    @hosts.setter
    def hosts(self, value):
        self._hosts = value

    @property
    def remediations(self):
        if self._remediations is None:
            self._server.load_scan_remediations(self)
        return self._remediations

    @remediations.setter
    def remediations(self, value):
        self._remediations = value

    def configure(self):
        """
        Changes the schedule or policy parameters of a scan.
        Params:
        Returns:
        """
        return

    def create(self):
        """
        Creates a scan.
        Params:
        Returns:
        """
        if self._server.server_version[0] == "5":
            params = {
                'policy_id': self.policy.object_id,
                'name': self.name,
                'tag_id': self.tag.id,
                'custom_targets': self.custom_targets
            }
            if self.target_file_name is not None:
                params['target_file_name'] = self.target_file_name

            response = self._server._api_request("POST", "/scan/new", params)
            if response is not None:
                self.id = response["scan"]["id"]
                self.uuid = response["scan"]["uuid"]
                self.status = response["scan"]["status"]
                for user in self.users:
                    if user.name == response["scan"]["owner"]:
                        self.owner = user
                return True
            else:
                return False
        elif self._server.server_version[0] == "6":
            params = {
                "uuid": self.template.uuid,
                "settings": {
                        "name": self.name,
                        "description": self.description,
                        "folder_id": self.tag.id,
                        "scanner_id": self.scanner.id if self.scanner is not None else 1,
                        "text_targets": self.custom_targets,
                        "file_targets": self.target_file_name if self.target_file_name is not None else "",
                        "launch": "ON_DEMAND",
                        "launch_now": True,
                        "emails": "",
                        "filter_type": "",
                        "filters": [],
                },
                "credentials": {},
                "plugins": {}
            }

            response = self._server._api_request("POST", "/scans", params)
            if response is not None:
                self.id = response["scan"]["id"]
                self.uuid = response["scan"]["uuid"]
                self.status = response["scan"]["status"]
                for user in self.users:
                    if user.name == response["scan"]["owner"]:
                        self.owner = user
                return True
            else:
                return False
        else:
            return False


    def delete(self):
        """
        Deletes a scan.
        Params:
        Returns:
        """
        if self._server.server_version[0] == "5":
            params = {
                'scan_uuid': self.uuid
            }
            response = self._server._api_request("POST", "/result/delete", params)
            if response is not None:
                return True
            else:
                return False
        elif self._server.server_version[0] == "6":
            response = self._server._api_request("DELETE", "/scans/%d" % self.id, "")
            if response is None:
                return True
            else:
                return False
        else:
            return False

    def delete_history(self):
        """
         Deletes historical results from a scan.
        Params:
        Returns:
        """
        return

    def details(self):
        """
        Returns details for the given scan.
        Params:
        Returns:
        """
        return

    def download(self):
        """
        Download an exported scan.
        Params:
        Returns:
        """
        return

    def export(self):
        """
        Export the given scan.
        Params:
        Returns:
        """
        return

    def export_status(self):
        """
        Check the file status of an exported scan.
        Params:
        Returns:
        """

    def host_details(self):
        """
         Returns details for the given host.
        Params:
        Returns:
        """
        return

    def _import(self):
        """
        Import an existing scan uploaded using Nessus.file.
        Params:
        Returns:
        """
        return

    def move(self, tag):
        """
        Move a scan from a tag to another.
        Params:
            tag(Tag): The tag where the scan will be placed.
        Returns:
            bool: True if successful, False otherwise.
        """
        if self._server.server_version[0] == "5":
            params = {
                'id': self.uuid,
                'tags': tag.id
            }
            response = self._server._api_request("POST", "/tag/replace", params)
            if response is not None:
                return True
            else:
                return False
        elif self._server.server_version[0] == "6":
            raise Exception("Not yet implemented.")
        else:
            return False

    def launch(self):
        """
        Launches a scan.
        Params:
        Returns:
        """


    def pause(self):
        """
        Pauses a scan.
        Params:
        Returns:
        """
        if self._server.server_version[0] == "5":
            params = {
                'scan_uuid': self.uuid
            }
            response = self._server._api_request("POST", "/scan/pause", params)
            if response is not None:
                return True
            else:
                return False
        elif self._server.server_version[0] == "6":
            response = self._server._api_request("POST", "/scans/%d/pause" % self.id, "")
            if response is not None:
                return True
            else:
                return False
        else:
            return False

    def stop(self):
        """
        Stops a scan.
        Params:
        Returns:
        """
        if self._server.server_version[0] == "5":
            params = {
                'scan_uuid': self.uuid
            }
            response = self._server._api_request("POST", "/scan/stop", params)
            if response is not None:
                return True
            else:
                return False
        elif self._server.server_version[0] == "6":
            response = self._server._api_request("POST", "/scans/%d/stop" % self.id, "")
            if response is not None:
                return True
            else:
                return False
        else:
            return False


    def resume(self):
        """
        Resumes a scan.
        Params:
        Returns:
        """
        if self._server.server_version[0] == "5":
            params = {
                'scan_uuid': self.uuid
            }
            response = self._server._api_request("POST", "/scan/resume", params)
            if response is not None:
                return True
            else:
                return False
        elif self._server.server_version[0] == "6":
            response = self._server._api_request("POST", "/scans/%d/resume" % self.id, "")
            if response is not None:
                return True
            else:
                return False
        else:
            return False

    def diff(self, _scan):
        """
        Create a diff report between scan1 and scan2.
        Params:
            scan1(Scan): first scan instance
            scan2(Scan): second scan instance
        Returns:
            bool: True if successful, False otherwise.
        """
        params = {
            'report1': self.id,
            'report2': _scan.id
        }
        response = self._server._api_request("POST", "/result/diff", params)
        if response is not None:
            scan = self._server.Scan()
            scan.uuid = response["report"]
            params = {
                "id": scan.uuid,
                "status": "read"
            }
            response = self._server._api_request("POST", "/result/status/set", params)
            if response is not None:
                return scan
            else:
                return None
        else:
            return None

    @property
    def vulnerabilities(self):
        """
        Load vulnerabilities results from scan.
        Params:
            scan(Scan): scan that we will load.
        Returns:
            True if successful, False otherwise.
        """
        if self._server.server_version[0] == "5":
            params = {
                'id': self.id
            }
            response = self._server._api_request("POST", "/result/details", params)
            if response is not None:
                self.vulnerabilities = []
                for vulnerability in response["vulnerabilities"]:
                    v = Vulnerability()
                    v.plugin_id = vulnerability["plugin_id"]
                    v.plugin_name = vulnerability["plugin_name"]
                    v.plugin_family = vulnerability["plugin_family"]
                    v.severity = vulnerability["severity"]
                    v.severity_index = vulnerability["severity_index"]
                    v.count = vulnerability["count"]
                    v.vuln_index = vulnerability["vuln_index"]
                    self.vulnerabilities.append(v)
                return True
            else:
                return False
        elif self._server.server_version[0] == "6":
            raise Exception("Not yet implemented.")
        else:
            return False

    @vulnerabilities.setter
    def vulnerabilities(self, value):
        if type(value) is list:
            self._vulnerabilities = value
        else:
            raise Exception("Invalid format.")

    @property
    def remediations(self):
        """
        Load a scan remediations content.
        :param scan:
        :return:
        """
        if self._server.server_version[0] == "5":
            params = {
                'id': self.id
            }
            response = self._server._api_request("POST", "/result/details", params)
            if response is not None:
                self.remediations = []
                if "remediations" in response["remediations"]:
                    for remediation in response["remediations"]["remediations"]:
                        r = Remediation()
                        r.text = remediation["remediation"]
                        r.value = remediation["value"]
                        r.vulns = remediation["vulns"]
                        r.hosts = remediation["hosts"]
                        self.remediations.append(r)
                return True
            else:
                return False
        elif self._server.server_version[0] == "6":
            raise Exception("Not yet implemented.")
        else:
            return False

    @remediations.setter
    def remediations(self, value):
        if type(value) is list:
            self._remediations = value
        else:
            raise Exception("Invalid format.")

    @property
    def notes(self):
        """
        Load a scan notes.
        Params:
            scan(Scan):
        Returns:
        """
        if self._server.server_version[0] == "5":
            params = {
                'id': self.id
            }
            response = self._server._api_request("POST", "/result/details", params)
            if response is not None:
                self.notes = []
                if "note" in response["notes"]:
                    for note in response["notes"]["note"]:
                        n = Note()
                        n.title = note["title"]
                        n.message = note["message"]
                        n.severity = note["severity"]
                        self.notes.append(n)
                return True
            else:
                return False
        elif self._server.server_version[0] == "6":
            raise Exception("Not yet implemented.")
        else:
            return False

    @notes.setter
    def notes(self, value):
        if type(value) is list:
            self._notes = value
        else:
            raise Exception("Invalid format")

    @property
    def hosts(self):
        """
        Load a scan notes.
        Params:
            scan(Scan):
        Returns:
        """
        if self._server.server_version[0] == "5":
            params = {
                'id': self.id
            }
            response = self._server._api_request("POST", "/result/details", params)
            if response is not None:
                self.hosts = []
                for host in response["hosts"]:
                    h = self.Host()
                    h.scan = self
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
                    self.hosts.append(h)
                return True
            else:
                return False
        elif self._server.server_version[0] == "6":
            raise Exception("Not yet implemented.")
        else:
            return False

    @hosts.setter
    def hosts(self, value):
        if type(value) is list:
            self._hosts = value
        else:
            raise Exception("Invalid format.")

    @staticmethod
    def timezones(self):
        """
        Returns the timezone list for creating a scan.
        """
        return


class Vulnerability(object):

    def __init__(self):
        self._id = None
        self._count = 0
        self._plugin_id = 0
        self._plugin_name = 0
        self._plugin_family = None
        self._vuln_index = 0
        self._severity = 0
        self._severity_index = 0

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        self._id = value

    @property
    def count(self):
        return self._count

    @count.setter
    def count(self, value):
        self._count = value

    @property
    def plugin_id(self):
        return self._plugin_id

    @plugin_id.setter
    def plugin_id(self, value):
        self._plugin_id = value

    @property
    def plugin_name(self):
        return self._plugin_name

    @plugin_name.setter
    def plugin_name(self, value):
        self._plugin_name = value

    @property
    def plugin_family(self):
        return self._plugin_family

    @plugin_family.setter
    def plugin_family(self, value):
        self._plugin_family = value

    @property
    def vuln_index(self):
        return self._vuln_index

    @vuln_index.setter
    def vuln_index(self, value):
        self._vuln_index = value

    @property
    def severity(self):
        return self._severity

    @severity.setter
    def severity(self, value):
        self._severity = value

    @property
    def severity_index(self):
        return self._severity_index

    @severity_index.setter
    def severity_index(self, value):
        self._severity_index = value


class Note(object):

    def __init__(self):
        self._title = None
        self._message = None
        self._severity = 0

    @property
    def title(self):
        return self._title

    @title.setter
    def title(self, value):
        self._title = value

    @property
    def message(self):
        return self._message

    @message.setter
    def message(self, value):
        self._message = value

    @property
    def severity(self):
        return self._severity

    @severity.setter
    def severity(self, value):
        self._severity = int(value)


class Remediation(object):
    """
    Scan remediation.

    Attributes:
        hosts(int): hosts concerned by the remediation
        vulns(int): quantity of vulnerabilities related to the remediation
        value(string): remediation content
        text(string): remediation content
    """

    def __init__(self):
        self._hosts = 0
        self._vulns = 0
        self._value = None
        self._text = None

    @property
    def hosts(self):
        return self._hosts

    @hosts.setter
    def hosts(self, value):
        self._hosts = int(value)

    @property
    def vulns(self):
        return self._vulns

    @vulns.setter
    def vulns(self, value):
        self._vulns = int(value)

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value):
        self._value = str(value)

    @property
    def text(self):
        return self._text

    @text.setter
    def text(self, value):
        self._text = str(value)