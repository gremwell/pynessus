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

class Policy(NessusObject):
    """
    A Nessus Policy instance.

    Params:
        id(int):
        template_uuid(string):
        name(string):
        description(string):
        owner_id(string):
        owner(string):
        shared(bool):
        user_permissions(int):
        creation_date(int):
        last_modification_date(int):
        visibility(bool):
        no_target(bool):
    """

    def __init__(self, server):
        super(Policy, self).__init__(server)
        self._id = 0
        self._template_uuid = None
        self._name = None
        self._description = None
        self._owner_id = None
        self._owner = None
        self._shared = False
        self._user_permissions = 0
        self._creation_date = 0
        self._last_modification_date = 0
        self._visibility = False
        self._no_target = False
        self._settings = None
        self._preferences = None
        self._plugins = None

    def configure(self):
        """
        Changes the parameters of a policy.
        Params:
        Returns:
        """
        return

    def copy(self):
        """
        Copy a policy.
        Params:
        Returns:
        """
        if self._server.server_version[0] == "5":
            params = {"policy_id": self.id}
            response = self._server._api_request("POST", "/policy/copy", params)
            if response is not None:
                _p = response["policy"]
                p = self._server.Policy()
                p.name = _p["policyname"]
                if "policycomments" in _p["policycontents"]:
                    p.description = _p["policycontents"]["policycomments"]
                for user in self._server.users:
                    if user.name == _p["policyowner"]:
                        self.owner = user
                p.id = _p["policyid"]
                p.visibility = _p["visibility"]
                return p
            else:
                return None
        elif self._server.server_version[0] == "6":
            response = self._server._api_request("POST", "/policies/%d/copy" % self.id, "")
            if response is not None:
                p = self._server.Policy()
                p.id = response["id"]
                p.name = response["name"]
                return p
            else:
                return None
        else:
            return None

    def create(self):
        """
        Create a policy.
        Params:
        Returns:
        """
        if self._server.server_version[0] == "5":
            params = {
                "policy_id": 0,
                "general.Basic.0": self.name,
                "general.Basic.1": self.description
            }
            if self._server.settings is not None:
                params = dict(params.items() + self._server.settings.items())
            response = self._server._api_request("POST", "/policy/update", params)
            if response is not None:
                self.id = response["metadata"]["id"]
                for user in self._server.users:
                    if user.name == response["metadata"]["owner"]:
                        self.owner = user
                self.visibility = response["metadata"]["visibility"]
                return True
            else:
                return False

        elif self._server.server_version[0] == "6":
            params = {
                "uuid": self.template_uuid,
                "settings": {
                    "name": self.name,
                    "description": self.description,
                    "acls": [{"permissions": "16", "type": "default"}],
                    "ping_the_remote_host": "yes",
                    "test_local_nessus_host": "yes",
                    "fast_network_discovery": "no",
                    "arp_ping": "yes",
                    "tcp_ping": "yes",
                    "tcp_ping_dest_ports": "built-in",
                    "icmp_ping": "yes",
                    "icmp_unreach_means_host_down": "no",
                    "icmp_ping_retries": "2",
                    "udp_ping": "no",
                    "scan_network_printers": "no",
                    "scan_netware_hosts": "no",
                    "wol_mac_addresses": "",
                    "wol_wait_time": "5",
                    "network_type": "Mixed (use RFC 1918)",
                    "unscanned_closed": "no",
                    "portscan_range": "default",
                    "ssh_netstat_scanner": "yes",
                    "wmi_netstat_scanner": "yes",
                    "snmp_scanner": "yes",
                    "only_portscan_if_enum_failed": "yes",
                    "verify_open_ports": "no",
                    "tcp_scanner": "no",
                    "syn_scanner": "yes",
                    "syn_firewall_detection": "Automatic (normal)",
                    "udp_scanner": "no",
                    "svc_detection_on_all_ports": "yes",
                    "detect_ssl": "yes",
                    "ssl_prob_ports": "Known SSL ports",
                    "enumerate_all_ciphers": "yes",
                    "check_crl": "no",
                    "report_paranoia": "Normal",
                    "thorough_tests": "no",
                    "av_grace_period": "0",
                    "smtp_domain": "example.com",
                    "smtp_from": "nobody@example.com",
                    "smtp_to": "postmaster@[AUTO_REPLACED_IP]",
                    "provided_creds_only": "yes",
                    "test_default_oracle_accounts": "no",
                    "scan_webapps": "no",
                    "request_windows_domain_info": "yes",
                    "enum_domain_users_start_uid": "1000",
                    "enum_domain_users_end_uid": "1200",
                    "enum_local_users_start_uid": "1000",
                    "enum_local_users_end_uid": "1200",
                    "win_known_bad_hashes": "",
                    "win_known_good_hashes": "",
                    "host_whitelist": "",
                    "report_verbosity": "Normal",
                    "report_superseded_patches": "no",
                    "silent_dependencies": "yes",
                    "allow_post_scan_editing": "yes",
                    "reverse_lookup": "no",
                    "log_live_hosts": "no",
                    "display_unreachable_hosts": "no",
                    "safe_checks": "yes",
                    "log_whole_attack": "no",
                    "stop_scan_on_disconnect": "no",
                    "slice_network_addresses": "no",
                    "reduce_connections_on_congestion": "no",
                    "use_kernel_congestion_detection": "no",
                    "network_receive_timeout": "5",
                    "max_checks_per_host": "5",
                    "max_hosts_per_scan": "20",
                    "max_simult_tcp_sessions_per_host": "",
                    "max_simult_tcp_sessions_per_scan": "",
                    "ssh_known_hosts": "",
                    "ssh_port": "22",
                    "ssh_client_banner": "OpenSSH_5.0",
                    "never_send_win_creds_in_the_clear": "yes",
                    "dont_use_ntlmv1": "yes",
                    "start_remote_registry": "no",
                    "enable_admin_shares": "no",
                    "apm_force_updates": "yes",
                    "apm_update_timeout": "5",
                    "http_login_method": "POST",
                    "http_login_max_redir": "0",
                    "http_login_invert_auth_regex": "no",
                    "http_login_auth_regex_on_headers": "no",
                    "http_login_auth_regex_nocase": "no",
                    "snmp_port": "161",
                    "additional_snmp_port1": "161",
                    "additional_snmp_port2": "161",
                    "additional_snmp_port3": "161",
                    "patch_audit_over_telnet": "no",
                    "patch_audit_over_rsh": "no",
                    "patch_audit_over_rexec": "no",
                    "aws_ui_region_type": "Rest of the World",
                    "aws_us_east_1": "no",
                    "aws_us_west_1": "no",
                    "aws_us_west_2": "no",
                    "aws_eu_west_1": "no",
                    "aws_ap_northeast_1": "no",
                    "aws_ap_southeast_1": "no",
                    "aws_ap_southeast_2": "no",
                    "aws_sa_east_1": "no",
                    "aws_us_gov_west_1": "no",
                    "aws_use_https": "yes",
                    "aws_verify_ssl": "yes"
                },
                "credentials": {},
                "plugins": {}
            }
            response = self._server._api_request("POST", "/policies", params)
            if response is not None:
                self.id = response["policy_id"]
                self.name = response["policy_name"]
                response2 = self._server._api_request("GET", "/policies/%d" % (self.id), "")
                if response2 is not None:
                    return True
                else:
                    return False
            else:
                return False
        else:
            return False

    def edit(self):
        """
        Edit a policy.
        Params:
        Returns:
        """
        if self._server.server_version[0] == "5":
            params = {
                "policy_id": self.id,
                "general.Basic.0": self.name,
                "general.Basic.1": self.description
            }
            if self.settings is not None:
                for k in self.settings:
                    params[k] = self.settings[k]
            response = self._server._api_request("POST", "/policy/update", params)
            if response is not None:
                self.id = response["metadata"]["id"]
                for user in self._server.users:
                    if user.name == response["metadata"]["owner"]:
                        self.owner = user
                self.visibility = response["metadata"]["visibility"]
                return True
            else:
                return False

        elif self._server.server_version[0] == "6":
            params = {
                "uuid": "ad629e16-03b6-8c1d-cef6-ef8c9dd3c658d24bd260ef5f9e66",
                "settings": {
                    "name": "My new policy",
                    "description": "Describe this new policy",
                    "acls": [{"permissions": "16", "type": "default"}],
                    "ping_the_remote_host": "yes",
                    "test_local_nessus_host": "yes",
                    "fast_network_discovery": "no",
                    "arp_ping": "yes",
                    "tcp_ping": "yes",
                    "tcp_ping_dest_ports": "built-in",
                    "icmp_ping": "yes",
                    "icmp_unreach_means_host_down": "no",
                    "icmp_ping_retries": "2",
                    "udp_ping": "no",
                    "scan_network_printers": "no",
                    "scan_netware_hosts": "no",
                    "wol_mac_addresses": "",
                    "wol_wait_time": "5",
                    "network_type": "Mixed (use RFC 1918)",
                    "unscanned_closed": "no",
                    "portscan_range": "default",
                    "ssh_netstat_scanner": "yes",
                    "wmi_netstat_scanner": "yes",
                    "snmp_scanner": "yes",
                    "only_portscan_if_enum_failed": "yes",
                    "verify_open_ports": "no",
                    "tcp_scanner": "no",
                    "syn_scanner": "yes",
                    "syn_firewall_detection": "Automatic (normal)",
                    "udp_scanner": "no",
                    "svc_detection_on_all_ports": "yes",
                    "detect_ssl": "yes",
                    "ssl_prob_ports": "Known SSL ports",
                    "enumerate_all_ciphers": "yes",
                    "check_crl": "no",
                    "report_paranoia": "Normal",
                    "thorough_tests": "no",
                    "av_grace_period": "0",
                    "smtp_domain": "example.com",
                    "smtp_from": "nobody@example.com",
                    "smtp_to": "postmaster@[AUTO_REPLACED_IP]",
                    "provided_creds_only": "yes",
                    "test_default_oracle_accounts": "no",
                    "scan_webapps": "no",
                    "request_windows_domain_info": "yes",
                    "enum_domain_users_start_uid": "1000",
                    "enum_domain_users_end_uid": "1200",
                    "enum_local_users_start_uid": "1000",
                    "enum_local_users_end_uid": "1200",
                    "win_known_bad_hashes": "",
                    "win_known_good_hashes": "",
                    "host_whitelist": "",
                    "report_verbosity": "Normal",
                    "report_superseded_patches": "no",
                    "silent_dependencies": "yes",
                    "allow_post_scan_editing": "yes",
                    "reverse_lookup": "no",
                    "log_live_hosts": "no",
                    "display_unreachable_hosts": "no",
                    "safe_checks": "yes",
                    "log_whole_attack": "no",
                    "stop_scan_on_disconnect": "no",
                    "slice_network_addresses": "no",
                    "reduce_connections_on_congestion": "no",
                    "use_kernel_congestion_detection": "no",
                    "network_receive_timeout": "5",
                    "max_checks_per_host": "5",
                    "max_hosts_per_scan": "20",
                    "max_simult_tcp_sessions_per_host": "",
                    "max_simult_tcp_sessions_per_scan": "",
                    "ssh_known_hosts": "",
                    "ssh_port": "22",
                    "ssh_client_banner": "OpenSSH_5.0",
                    "never_send_win_creds_in_the_clear": "yes",
                    "dont_use_ntlmv1": "yes",
                    "start_remote_registry": "no",
                    "enable_admin_shares": "no",
                    "apm_force_updates": "yes",
                    "apm_update_timeout": "5",
                    "http_login_method": "POST",
                    "http_login_max_redir": "0",
                    "http_login_invert_auth_regex": "no",
                    "http_login_auth_regex_on_headers": "no",
                    "http_login_auth_regex_nocase": "no",
                    "snmp_port": "161",
                    "additional_snmp_port1": "161",
                    "additional_snmp_port2": "161",
                    "additional_snmp_port3": "161",
                    "patch_audit_over_telnet": "no",
                    "patch_audit_over_rsh": "no",
                    "patch_audit_over_rexec": "no",
                    "aws_ui_region_type": "Rest of the World",
                    "aws_us_east_1": "no",
                    "aws_us_west_1": "no",
                    "aws_us_west_2": "no",
                    "aws_eu_west_1": "no",
                    "aws_ap_northeast_1": "no",
                    "aws_ap_southeast_1": "no",
                    "aws_ap_southeast_2": "no",
                    "aws_sa_east_1": "no",
                    "aws_us_gov_west_1": "no",
                    "aws_use_https": "yes",
                    "aws_verify_ssl": "yes"
                },
                "credentials": {},
                "plugins": {}
            }
            if self.settings is not None:
                params = dict(params.items() + self.settings.items())
            response = self._server._api_request("PUT", "/policies/%d" % self.id, params)
            if response is None:
                return True
            else:
                return False
        else:
            return False

    def delete(self):
        """
        Delete a policy.
        Params:
        Returns:
        """
        if self._server.server_version[0] == "5":
            params = {
                "policy_id": self.id
            }
            response = self._server._api_request("POST", "/policy/delete", params)
            if response is not None:
                return True
            else:
                return False
        elif self._server.server_version[0] == "6":
            response = self._server._api_request("DELETE", "/policies/%d" % self.id, "")
            if response is None:
                return True
            else:
                return False
        else:
            return False

    def details(self):
        """
        Returns details for the given policy.
        Params:
        Returns:
        """
        raise Exception("Not yet implemented.")

    def _import(self):
        """
        Import an existing policy uploaded using Nessus.file (.nessus format only).
        Params:
        Returns:
        """
        raise Exception("Not yet implemented.")

    def export(self, filename=None):
        """
        Export the given policy.
        Params:
        Returns:
        """
        if self._server.server_version[0] == "5":
            if filename is None:
                filename = "nessus_policy_%s.nessus" % self.name
            response = self._server._request("GET", "/policy/download?policy_id=%d" % self.id, "")
            with open(filename, "wb") as f:
                f.write(response)
            return filename
        elif self._server.server_version[0] == "6":
            raise Exception("Not yet implemented.")
        else:
            return False

    def preferences(self):
        """
        Load and assign policy preferences
        Params:
            policy(Policy): policy instance
        Returns:
        """

        if self._server.server_version[0] == "5":
            params = {
                "policy_id": self.id
            }
            response = self._server._api_request("POST", "/policy/list/plugins/preferences", params)
            if response is not None:
                self.preferences = []
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
                        self.preferences.append(p)
                return True
            else:
                return False
        else:
            raise Exception("Not supported")

    def plugins(self):
        """
        Load policy plugins
        Params:
        Returns:
        """
        if self._server.server_version[0] == "5":
            params = {
                "policy_id": self.id
            }
            response = self._server._api_request("POST", "/policy/list/families", params)
            if response is not None:
                if "family" in response["policyfamilies"]:
                    families = []
                    for family in response["policyfamilies"]["family"]:
                        pf = self._server.PluginFamily()
                        pf.name = family["name"]
                        pf.id = family["id"]
                        pf.plugin_count = family["plugin_count"]
                        pf.status = family["status"]
                        params2 = {
                            "policy_id": self.id,
                            "family_id": pf.id
                        }
                        response2 = self._api_request("POST", "/policy/list/plugins", params2)
                        if response2 is not None:
                            for plugin in response2["policyplugins"]["plugin"]:
                                p = self._server.Plugin()
                                p.name = plugin["pluginname"]
                                p.filename = plugin["pluginfilename"]
                                p.id = plugin["pluginid"]
                                p.status = plugin["status"]
                                pf.plugins.append(p)
                        families.append(pf)
                    self.plugins = families
                return True
            else:
                return False
        else:
            raise Exception("Not supported.")

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = str(value)

    @property
    def description(self):
        return self._description

    @description.setter
    def description(self, value):
        self._description = str(value)

    @property
    def owner(self):
        return self._owner

    @owner.setter
    def owner(self, value):
        self._owner = str(value)

    @property
    def visibility(self):
        return self._visibility

    @visibility.setter
    def visibility(self, value):
        self._visibility = str(value)

    @property
    def shared(self):
        return self._shared

    @shared.setter
    def shared(self, value):
        self._shared = bool(value)

    @property
    def user_permissions(self):
        return self._user_permissions

    @user_permissions.setter
    def user_permissions(self, value):
        self._user_permissions = int(value)

    @property
    def last_modification_date(self):
        return self._last_modification_date

    @last_modification_date.setter
    def last_modification_date(self, value):
        self._last_modification_date = int(value)

    @property
    def creation_date(self):
        return self._creation_date

    @creation_date.setter
    def creation_date(self, value):
        self._creation_date = int(value)

    @property
    def no_target(self):
        return self._no_target

    @no_target.setter
    def no_target(self, value):
        self._no_target = bool(value)

    @property
    def settings(self):
        return self._settings

    @settings.setter
    def settings(self, value):
        if type(value) is list:
            self._settings = value
        else:
            raise Exception("Invalid format.")

    @property
    def preferences(self):
        return self._preferences

    @preferences.setter
    def preferences(self, value):
        if type(value) is list:
            self._preferences = value
        else:
            raise Exception("Invalid format.")

    @property
    def plugins(self):
        return self._plugins

    @plugins.setter
    def plugins(self, value):
        if type(value) is list:
            self._plugins = value
        else:
            raise Exception("Invalid format.")

    @property
    def template_uuid(self):
        return self._template_uuid

    @template_uuid.setter
    def template_uuid(self, value):
        self._template_uuid = str(value)


class PreferenceValue(object):
    """
    Policy preference value.
    """
    def __init__(self):
        self._id = -1
        self._name = None
        self._type = "entry"

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
    def name(self, value):
        self._name = value

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        self._type = value


class Preference(object):
    """
    Policy preference instance.
    """
    def __init__(self):

        self._name = None
        self._values = []

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def values(self):
        return self._values

    @values.setter
    def values(self, value):
        self._values = value
