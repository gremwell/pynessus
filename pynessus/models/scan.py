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
        self._owner = None
        self._shared = False
        self._type = None
        self._uuid = None
        self._policy = None
        self._scanner = None
        self._custom_targets = None
        self._target_file_name = None
        self._vulnerabilities = None
        self._notes = None
        self._remediations = None
        self._hosts = None

    def launch(self):
        return self._server.create_scan(self)

    def pause(self):
        if self._id is not None:
            self._server.pause_scan(self)

    def resume(self):
        if self._id is not None:
            self._server.resume_scan(self)

    def stop(self):
        if self._id is not None:
            self._server.stop_scan(self)

    def progress(self):
        if self._id is not None:
            return self._server.get_scan_progress(self)

    def diff(self, dscan):
        if self._id is not None:
            return self._server.load_scan_diff(self, dscan)

    @property
    def status(self):
        return self._status

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


class Host(NessusObject):

    def __init__(self, server):
        super(Host, self).__init__(server)
        self._scan = None
        self._host_index = 0
        self._totalchecksconsidered = 0
        self._numchecksconsidered = 0
        self._scanprogresstotal = 0
        self._scanprogresscurrent = 0
        self._score = 0
        self._progress = None
        self._critical = 0
        self._high = 0
        self._medium = 0
        self._low = 0
        self._info = 0
        self._severity = 0
        self._host_id = 0
        self._hostname = None

        self._ip = None
        self._fqdn = None
        self._start = None
        self._end = None
        self._vulnerabilities = None

    @property
    def host_index(self):
        return self._host_index

    @host_index.setter
    def host_index(self, value):
        self._host_index = value

    @property
    def totalchecksconsidered(self):
        return self._totalchecksconsidered

    @totalchecksconsidered.setter
    def totalchecksconsidered(self, value):
        self._totalchecksconsidered = value

    @property
    def numchecksconsidered(self):
        return self._numchecksconsidered

    @numchecksconsidered.setter
    def numchecksconsidered(self, value):
        self._numchecksconsidered = value

    @property
    def scanprogresstotal (self):
        return self._scanprogresstotal

    @scanprogresstotal .setter
    def scanprogresstotal (self, value):
        self._scanprogresstotal = value

    @property
    def scanprogresscurrent(self):
        return self._scanprogresscurrent

    @scanprogresscurrent.setter
    def scanprogresscurrent(self, value):
        self._scanprogresscurrent = value

    @property
    def score(self):
        return self._score

    @score.setter
    def score(self, value):
        self._score = value

    @property
    def progress(self):
        return self._progress

    @progress.setter
    def progress(self, value):
        self._progress = value

    @property
    def critical(self):
        return self._critical

    @critical.setter
    def critical(self, value):
        self._critical = value

    @property
    def high(self):
        return self._high

    @high.setter
    def high(self, value):
        self._high = value

    @property
    def medium(self):
        return self._medium

    @medium.setter
    def medium(self, value):
        self._medium = value

    @property
    def low(self):
        return self._low

    @low.setter
    def low(self, value):
        self._low = value

    @property
    def info(self):
        return self._info

    @info.setter
    def info(self, value):
        self._info = value

    @property
    def severity(self):
        return self._severity

    @severity.setter
    def severity(self, value):
        self._severity = value

    @property
    def host_id(self):
        return self._host_id

    @host_id.setter
    def host_id(self, value):
        self._host_id = value

    @property
    def hostname(self):
        return self._hostname

    @hostname.setter
    def hostname(self, value):
        self._hostname = value

    @property
    def ip(self):
        return self._ip

    @ip.setter
    def ip(self, value):
        self._ip = value

    @property
    def fqdn(self):
        return self._fqdn

    @fqdn.setter
    def fqdn(self, value):
        self._fqdn = value

    @property
    def start(self):
        return self._start

    @start.setter
    def start(self, value):
        self._start = value

    @property
    def end(self):
        return self._end

    @end.setter
    def end(self, value):
        self._end = value

    @property
    def vulnerabilities(self):
        if self._vulnerabilities is None:
            self._server.load_host_vulnerabilities(self)
        return self._vulnerabilities

    @vulnerabilities.setter
    def vulnerabilities(self, value):
        self._vulnerabilities = value

    @property
    def scan(self):
        return self._scan

    @scan.setter
    def scan(self, value):
        self._scan = value


class Remediation(object):

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