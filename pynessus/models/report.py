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

class Report(NessusObject):
    """
    A Nessus Report instance.

    Attributes:

    _Google Python Style Guide:
    http://google-styleguide.googlecode.com/svn/trunk/pyguide.html
    """

    def __init__(self, server):
        """Constructor"""
        super(Report, self).__init__(server)
        self._name = None
        self._readable_name = None
        self._status = None
        self._timestamp = 0
        self._content = None
        self._format = "nessus.v2"

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name):
        self._name = name

    @property
    def readable_name(self):
        return self._readable_name

    @readable_name.setter
    def readable_name(self, readable_name):
        self._readable_name = readable_name

    @property
    def status(self):
        return self._status

    @status.setter
    def status(self, status):
        self._status = status

    @property
    def timestamp(self):
        return self._timestamp

    @timestamp.setter
    def timestamp(self, timestamp):
        self._timestamp = timestamp

    @property
    def content(self):
        return self._content

    @content.setter
    def content(self, content):
        self._content = content

    @property
    def format(self):
        return self._format

    @format.setter
    def format(self, _format):
        self._format = _format

    def download(self, filename=None, fmt="nessus.v2"):
        """
        Save the report content to a file.
        Params:
            filename(string): filename
        Returns:
            True if successful, False otherwise.
        """
        if self._id is not None:
            self._server.load_report(self, fmt)
            if filename is None:
                filename = "%s.%s" % (self._id, self._format)
            with open(filename, "wb") as f:
                f.write(self.content)
            return filename