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


class Mail(NessusObject):
    """
    A Nessus server mail settings.

    Attributes:
        smtp_host(str):
        smtp_port(str):
        smtp_from(str):
        smtp_www_host(str):
        smtp_auth(str):
        smtp_user(str):
        smtp_pass(str):
        smtp_enc(str):

    _Google Python Style Guide:
    http://google-styleguide.googlecode.com/svn/trunk/pyguide.html
    """

    def __init__(self, server):
        """Constructor"""
        super(Mail, self).__init__(server)
        self._smtp_host = None
        self._smtp_port = None
        self._smtp_from = None
        self._smtp_www_host = None
        self._smtp_auth = None
        self._smtp_user = None
        self._smtp_pass = None
        self._smtp_enc = None

    def load(self):
        if self._server.server_version[0] == "6":
            response = self._server._api_request(
                "GET",
                "/settings/network/mail",
                ""
            )
            if response is not None:
                self._smtp_host = response["smtp_host"]
                self._smtp_port = response["smtp_port"]
                self._smtp_from = response["smtp_from"]
                self._smtp_www_host = response["smtp_www_host"]
                self._smtp_auth = response["smtp_auth"]
                self._smtp_user = response["smtp_user"]
                self._smtp_pass = response["smtp_pass"]
                self._smtp_enc = response["smtp_enc"]
                return True
            else:
                return False
        else:
            raise Exception("Not supported.")

    def update(self):
        """
        Update the mail settings.
        Params:
        Returns:
        """
        if self._server.server_version[0] == "6":
            response = self._server._api_request(
                "PUT",
                "/settings/network/mail",
                {
                    "smtp_host": self._smtp_host,
                    "smtp_port": self._smtp_port,
                    "smtp_from": self._smtp_from,
                    "smtp_www_host": self._smtp_www_host,
                    "smtp_auth": self._smtp_auth,
                    "smtp_user": self._smtp_user,
                    "smtp_pass": self._smtp_pass,
                    "smtp_enc": self._smtp_enc,
                }
            )
            if response is None:
                return True
            else:
                return False
        else:
            raise Exception("Not supported.")

    @property
    def smtp_host(self):
        return self._smtp_host

    @smtp_host.setter
    def smtp_host(self, value):
        self._smtp_host = str(value)

    @property
    def smtp_port(self):
        return self._smtp_port

    @smtp_port.setter
    def smtp_port(self, value):
        self._smtp_port = str(value)

    @property
    def smtp_from(self):
        return self._smtp_from

    @smtp_from.setter
    def smtp_from(self, value):
        self._smtp_from = str(value)

    @property
    def smtp_www_host(self):
        return self._smtp_www_host

    @smtp_www_host.setter
    def smtp_www_host(self, value):
        self._smtp_www_host = str(value)

    @property
    def smtp_auth(self):
        return self._smtp_auth

    @smtp_auth.setter
    def smtp_auth(self, value):
        self._smtp_auth = str(value)

    @property
    def smtp_user(self):
        return self._smtp_user

    @smtp_user.setter
    def smtp_user(self, value):
        self._smtp_user = str(value)

    @property
    def smtp_pass(self):
        return self._smtp_pass

    @smtp_pass.setter
    def smtp_pass(self, value):
        self._smtp_pass = str(value)

    @property
    def smtp_enc(self):
        return self._smtp_enc

    @smtp_enc.setter
    def smtp_enc(self, value):
        self._smtp_enc = str(value)