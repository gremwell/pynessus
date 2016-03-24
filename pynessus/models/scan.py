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
from time import sleep
from nessusobject import NessusObject
from vulnerability import Vulnerability
from host import Host
REPORT_CHAPTERS = [
    "vuln_hosts_summary",
    "vuln_by_host",
    "compliance_exec",
    "remediations",
    "vuln_by_plugin",
    "compliance"
]

FORMATS = [
    "nessus",
    "csv",
    "pdf",
    "html",
    "db"
]


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
        self._folder = None
        self._comphosts = None
        self._compliance = None
        self._history = None
        self._filters = None

    @property
    def status(self):
        """
        Get the scan status (i.e. running, completed, paused, stopped)
        Params:
            scan(Scan):
        Returns:
            string: current scan status
        """
        response = self._server._api_request("GET", "/scans/%d" % self.id)
        self._status = response["info"]["status"]
        return self._status

    @status.setter
    def status(self, status):
        self._status = status

    @property
    def progress(self):
        """
        Get the scan progress (expressed in percentages).
        Params:
            scan(Scan):
        Returns:
        """
        response = self._server._api_request("GET", "/scans/%d" % self.id)
        current = 0.0
        total = 0.0
        for host in response["hosts"]:
            current += host["scanprogresscurrent"]
            total += host["scanprogresstotal"]
        return current/(total if total else 1.0)*100.0

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        self._id = int(value)

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

    @property
    def folder(self):
        return self._folder

    @folder.setter
    def folder(self, value):
        self._folder = value

    @property
    def comphosts(self):
        return self._comphosts

    @comphosts.setter
    def comphosts(self, value):
        self._comphosts = value

    @property
    def compliance(self):
        return self._compliance

    @compliance.setter
    def compliance(self, value):
        self._compliance = value

    @property
    def history(self):
        return self._history

    @history.setter
    def history(self, value):
        self._history = value

    @property
    def filters(self):
        return self._filters

    @filters.setter
    def filters(self, value):
        self._filters = value

    def configure(self):
        """
        Changes the schedule or policy parameters of a scan.
        Params:
        Returns:
        """
        response = self._server._api_request("POST", "/scans/%d/copy" % self.id)
        if response is not None:
            scan = self._server.Scan()
            scan.creation_date = response["creation_date"]
            scan.custom_targets = response["custom_targets"] if "custom_targets" in response else None
            scan.default_permissions = response["default_permisssions"] if "default_permisssions" in response else None
            scan.description = response["description"] if "description" in response else None
            scan.emails = response["emails"] if "emails" in response else None
            scan.id = response["id"]
            scan.last_modification_date = response["last_modification_date"]
            scan.name = response["name"]
            scan.notification_filter_type = response["notification_filter_type"] if "notification_filter_type" in response else None
            scan.notififcation_filters = response["notification_filters"] if "notification_filters" in response else None
            if "owner_id" in response:
                for user in self.server.users:
                    if user.id == response["owner_id"]:
                        scan.owner = user
            if "policy_id" in response:
                for policy in self.server.policies:
                    if policy.id == response["policy_id"]:
                        scan.policy = policy

            scan.rrules = response["rrules"] if "rrules" in response else None
            if "scanner_id" in response:
                for scanner in self.server.scanners:
                    if scanner.id == response["scanner_id"]:
                        scan.scanner = scanner
            scan.shared = response["shared"] if "shared" in response else None
            scan.starttime = response["starttime"] if "starttime" in response else None
            scan.tag_id = response["tag_id"] if "tag_id" in response else None
            scan.timezone = response["timezone"] if "timezone" in response else None
            scan.type = response["type"] if "type" in response else None
            scan.user_permissions = response["user_permissions"] if "user_permissions" in response else None
            scan.template = self._server.Template()
            scan.template.uuid = response["uuid"]
            scan.use_dashboard = response["use_dashboard"] if "use_dashboard" in response else None
            return scan
        else:
            return False

    def create(self):
        """
        Creates a scan.
        Params:
        Returns:
        """
        params = {
            "uuid": self.policy.template_uuid,
            "settings": {
                    "name": self.name,
                    "description": self.description,
                    "folder_id": self.tag.id,
                    "scanner_id": self.scanner.id if self.scanner is not None else 1,
                    "policy_id": self.policy.id,
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
        if "scan" in response and response["scan"] is not None:
            self.id = response["scan"]["id"]
            self.uuid = response["scan"]["uuid"]
            for user in self._server.users:
                if user.name == response["scan"]["owner"]:
                    self.owner = user
            return True
        else:
            return False

    def delete(self):
        """
        Deletes a scan.
        Params:
        Returns:
        """
        response = self._server._api_request("DELETE", "/scans/%d" % self.id, "")
        if response is None:
            return True
        else:
            return False

    def delete_history(self, history_id):
        """
        Deletes historical results from a scan.
        Params:
        Returns:
        """
        response = self._server._api_request("DELETE", "/scans/%d/history/%d" % (self.id, history_id))
        if response is None:
            return True
        else:
            return False

    def details(self):
        """
        Returns details for the given scan.
        Params:
        Returns:
        """
        response = self._server._api_request("GET", "/scans/%d" % self.id, "")
        self.hosts = []
        if "comphosts" in response and response["comphosts"] is not None:
            for host in response["hosts"]:
                h = Host(self._server)
                h.scan = self
                h.host_id = host["host_id"]
                h.host_index = host["host_index"]
                h.hostname = host["hostname"]
                h.progress = host["progress"]
                h.critical = host["critical"]
                h.high = host["high"]
                h.medium = host["medium"]
                h.low = host["low"]
                h.info = host["info"]
                h.totalchecksconsidered = host["totalchecksconsidered"]
                h.numchecksconsidered = host["numchecksconsidered"]
                h.scanprogresstotal = host["scanprogresstotal"]
                h.scanprogresscurrent = host["scanprogresscurrent"]
                h.score = host["score"]
                self.hosts.append(h)

        self.comphosts = []
        if "comphosts" in response and response["comphosts"] is not None:
            for host in response["comphosts"]:
                h = Host(self._server)
                h.host_id = host["host_id"]
                h.host_index = host["host_index"]
                h.hostname = host["hostname"]
                h.progress = host["progress"]
                h.critical = host["critical"]
                h.high = host["high"]
                h.medium = host["medium"]
                h.low = host["low"]
                h.info = host["info"]
                h.totalchecksconsidered = host["totalchecksconsidered"]
                h.numchecksconsidered = host["numchecksconsidered"]
                h.scanprogresstotal = host["scanprogresstotal"]
                h.scanprogresscurrent = host["scanprogresscurrent"]
                h.score = host["schore"]
                self.comphosts.append(h)
        self.notes = []
        if "notes" in response and response["notes"] is not None:
            for note in response["notes"]["note"]:
                n = Note()
                n.title = note["title"]
                n.message = note["message"]
                n.severity = note["severity"]
                self.notes.append(n)

        self.remediations = []
        if ("remediations" in response and response["remediations"] is not None) and \
                ("remediations" in response["remediations"] and
                         response["remediations"]["remediations"] is not None):
            for remediation in response["remediations"]["remediations"]:
                r = Remediation()
                r.value = remediation["value"]
                r.hosts = remediation["hosts"]
                r.vulns = remediation["vulns"]
                r.text = remediation["remediation"]
                self.remediations.append(r)

        self.vulnerabilities = []
        if "vulnerabilities" in response and response["vulnerabilities"] is not None:
            for vulnerability in response["vulnerabilities"]:
                v = self._server.Vulnerability()
                v.plugin_id = vulnerability["plugin_id"]
                v.plugin_name = vulnerability["plugin_name"]
                v.plugin_family = vulnerability["plugin_family"]
                v.count = vulnerability["count"]
                v.vuln_index = vulnerability["vuln_index"]
                v.severity_index = vulnerability["severity_index"]
                self.vulnerabilities.append(v)

        self.compliance = []
        if "compliance" in response and response["compliance"] is not None:
            for vulnerability in response["compliance"]:
                v = self._server.Vulnerability()
                v.plugin_id = vulnerability["plugin_id"]
                v.plugin_name = vulnerability["plugin_name"]
                v.plugin_family = vulnerability["plugin_family"]
                v.count = vulnerability["count"]
                v.vuln_index = vulnerability["vuln_index"]
                v.severity_index = vulnerability["severity_index"]
                self.compliance.append(v)

        self.history = []
        if "history" in response and response["history"] is not None:
            for history in response["history"]:
                h = History()
                h.history_id = history["history_id"]
                h.uuid = history["uuid"]
                h.status = history["status"]
                h.owner_id = history["owner_id"]
                h.creation_date = history["creation_date"]
                h.last_modification_date = history["last_modification_date"]
                self.history.append(h)

        self.filters = []
        if "filters" in response and response["filters"] is not None:
            for filt in response["filters"]:
                f = Filter()
                f.name = filt["name"]
                f.readable_name = filt["readable_name"]
                f.operators = filt["operators"]
                f.control = filt["control"]

        for user in self._server.users:
            if user.id == response["owner_id"]:
                self.owner = user
        return True

    def download(self, filename=None, fmt="nessus", password=None, chapters=";".join(REPORT_CHAPTERS)):
        """
        Download an exported scan.
        Params:
        Returns:
        """

        response = self._server._api_request("GET", "/scans", "")
        self._scans = []
        if "scans" in response and response["scans"] is not None:
            for s in response["scans"]:
                r_response = self._server._api_request(
                    "POST",
                    "/scans/%d/export" % s["id"],
                    {"format": fmt, "password": password, chapters: ";".join(REPORT_CHAPTERS)}
                )
                if "file" in r_response:
                    status = None
                    while status != "ready":
                        content = self._server._api_request(
                            "GET", "/scans/%d/export/%d/status" % (s["id"], r_response["file"]))
                        if content is not None:
                            status = content["status"]
                        sleep(1)
                    content = self._server._request("GET", "/scans/%d/export/%d/download" % (s["id"], r_response["file"]), "")
                    if filename is None:
                        filename = "%s_%s.%s" % (self._name, self._uuid, fmt)
                    with open(filename, "wb") as f:
                        f.write(content)
                    return filename
        return None

    def move(self, tag):
        """
        Move a scan from a tag to another.
        Params:
            tag(Tag): The tag where the scan will be placed.
        Returns:
            bool: True if successful, False otherwise.
        """
        raise Exception("Not yet implemented.")

    def copy(self):
        """
        Copy a scan .
        Params:
        Returns:
            scan: Copied scan if successful, False otherwise.
        """

        response = self._server._api_request("POST", "/scans/%d/copy" % self.id)
        scan = self._server.Scan()
        scan.status = response["status"]
        scan.enabled = response["enabled"]
        scan.name = response["name"]
        scan.read = response["read"]
        scan.last_modification_date = response["last_modification_date"]
        scan.creation_date = response["creation_date"]
        scan.user_permissions = response["user_permissions"]
        scan.shared = response["shared"]
        scan.id = response["id"]
        scan.template = self._server.Template()
        scan.template.uuid = response["uuid"]
        if "folder_id" in response:
            scan.folder = self._server.Folder()
            scan.folder.id = response["folder_id"]
        for user in self._server.users:
            if user.id == response["owner_id"]:
                scan.owner = user
        return scan

    def launch(self):
        """
        Launches a scan.
        Params:
        Returns:
        """
        return self.create()

    def pause(self):
        """
        Pauses a scan.
        Params:
        Returns:
        """
        response = self._server._api_request("POST", "/scans/%d/pause" % self.id)
        if response is None:
            return True
        else:
            return False

    def stop(self):
        """
        Stops a scan.
        Params:
        Returns:
        """
        response = self._server._api_request("POST", "/scans/%d/stop" % self.id, "")
        if response is None:
            return True
        else:
            return False

    def resume(self):
        """
        Resumes a scan.
        Params:
        Returns:
        """
        response = self._server._api_request("POST", "/scans/%d/resume" % self.id, "")
        if response is None:
            return True
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

    def information(self):
        self.details()
        severity = ["Informational", "Low", "Medium", "High", "Critical"]
        information = ""
        for host in self.hosts:
            for vuln in host.vulnerabilities:
                if vuln.plugin_name == "Nessus Scan Information":
                    response = self._server._api_request(
                        "GET",
                        "/scans/%d/hosts/%d/plugins/%d" % (self.id, host.host_id, vuln.plugin_id)
                    )
                    if "outputs" in response:
                        information += response["outputs"][0]["plugin_output"]

        information += "\n\t\t\t[[ Scan results ]]"
        for host in self.hosts:
            information += "\n# Host [%s]\n" % host.hostname
            for vuln in host.vulnerabilities[::-1]:
                information += "\n\t * %s - %s" % (vuln.plugin_name, severity[vuln.severity])
        information += "\n"
        return information

    @property
    def vulnerabilities(self):
        """
        Load vulnerabilities results from scan.
        Params:
            scan(Scan): scan that we will load.
        Returns:
            True if successful, False otherwise.
        """
        return self._vulnerabilities

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
        return self._remediations

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
        return self._notes

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
        return self._hosts

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


class History(object):
    """
    Scan history.

    Attributes:
        history_id(int):
        uuid(string):
        owner_id(int):
        status(string):
        creation_date(int):
        last_modification_date(int):
    """

    def __init__(self):
        self._history_id = 0
        self._uuid = None
        self._owner_id = 0
        self._status = None
        self._creation_date = 0
        self._last_modification_date = 0

    @property
    def history_id(self):
        return self._history_id

    @history_id.setter
    def history_id(self, value):
        self._history_id = int(value)

    @property
    def uuid(self):
        return self._uuid

    @uuid.setter
    def uuid(self, value):
        self._uuid = str(value)

    @property
    def owner_id(self):
        return self._owner_id

    @owner_id.setter
    def owner_id(self, value):
        self._owner_id = int(value)

    @property
    def status(self):
        return self._status

    @status.setter
    def status(self, value):
        self._status = str(value)

    @property
    def creation_date(self):
        return self._creation_date

    @creation_date.setter
    def creation_date(self, value):
        self._creation_date = int(value)

    @property
    def last_modification_date(self):
        return self._last_modification_date

    @last_modification_date.setter
    def last_modification_date(self, value):
        self._last_modification_date = int(value)


class Filter(object):
    """
    Scan filter.

    Attributes:
        name(int):
        readable_name(string):
        operators(array):
        controls(dict):
    """

    def __init__(self):
        self._name = None
        self._readable_name = None
        self._operators = []
        self._controls = {}

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = str(value)

    @property
    def readable_name(self):
        return self._readable_name

    @readable_name.setter
    def readable_name(self, value):
        self._readable_name = str(value)

    @property
    def operators(self):
        return self._operators

    @operators.setter
    def operators(self, value):
        self._operators = value

    @property
    def controls(self):
        return self._controls

    @controls.setter
    def controls(self, value):
        self._controls = value
