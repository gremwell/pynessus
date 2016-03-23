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
from vulnerability import Vulnerability


class Host(NessusObject):
    """
    Scanned host.

    Attributes:

    """
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
        response = self._server._api_request("GET", "/scans/%d/hosts/%d" % (self.scan.id, self.host_id))
        if response is not None and "vulnerabilities" in response:
            self._vulnerabilities = []
            for vulnerability in response["vulnerabilities"]:
                v = self._server.Vulnerability()
                v.host = self
                v.plugin_id = vulnerability["plugin_id"]
                v.plugin_name = vulnerability["plugin_name"]
                v.plugin_family = vulnerability["plugin_family"]
                v.severity = vulnerability["severity"]
                v.severity_index = vulnerability["severity_index"]
                v.count = vulnerability["count"]
                v.vuln_index = vulnerability["vuln_index"]
                self._vulnerabilities.append(v)
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



    def compliance(self, host):
        """

        :param host:
        :return:
        """
        raise Exception("Not yet implemented.")