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


class Proxy(NessusObject):
    """
    A Nessus server proxy settings.

    Attributes:
        proxy(str):
        proxy_port(str):
        proxy_usernamestr):
        proxy_password(str):
        user_agent(str):

    _Google Python Style Guide:
    http://google-styleguide.googlecode.com/svn/trunk/pyguide.html
    """

    def __init__(self, server):
        """Constructor"""
        super(Proxy, self).__init__(server)
        self._proxy = None
        self._proxy_port = None
        self._proxy_username = None
        self._proxy_password = None
        self._user_agent = None

    def load(self):
        """
        Loads the proxy settings
        This request requires system administrator user permissions.
        :return:
        """
        if self._server.server_version[0] == "6":
            response = self._server._api_request(
                "GET",
                "/settings/network/proxy",
                ""
            )
            if response is not None:
                self.proxy = response["proxy"]
                self.proxy_port = response["proxy_port"]
                self.proxy_username = response["proxy_username"]
                self.proxy_password = response["proxy_password"]
                self.user_agent = response["user_agent"]
                return True
            else:
                return False
        else:
            raise Exception("Not supported.")

    def update(self):
        """
        Update the proxy settings.
        Params:
        Returns:
        """
        if self._server.server_version[0] == "6":
            response = self._server._api_request(
                "PUT",
                "/settings/network/proxy",
                {
                    "proxy": self._proxy,
                    "proxy_port": self._proxy_port,
                    "proxy_username": self._proxy_username,
                    "proxy_password": self._proxy_password,
                    "user_agent": self._user_agent,
                }
            )
            if response is None:
                return True
            else:
                return False
        else:
            raise Exception("Not supported.")

    @property
    def proxy(self):
        return self._proxy

    @proxy.setter
    def proxy(self, value):
        self._proxy = str(value)

    @property
    def proxy_port(self):
        return self._proxy_port

    @proxy_port.setter
    def proxy_port(self, value):
        self._proxy_port = int(value)

    @property
    def proxy_username(self):
        return self._proxy_username

    @proxy_username.setter
    def proxy_username(self, value):
        self._proxy_username = str(value)

    @property
    def proxy_password(self):
        return self._proxy_password

    @proxy_password.setter
    def proxy_password(self, value):
        self._proxy_password = str(value)

    @property
    def user_agent(self):
        return self._user_agent

    @user_agent.setter
    def user_agent(self, value):
        self._user_agent = str(value)