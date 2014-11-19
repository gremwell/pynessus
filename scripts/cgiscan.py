__author__ = 'quentin'
import ConfigParser
from optparse import OptionParser
from pynessus.nessus import Nessus
from pynessus.models.user import User
from pynessus.models.policy import Policy


if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-f", dest='format', help="report file format", default="nessus.v2")
    parser.add_option("-c", dest='configfile', default='nessus.conf', help="configuration file to use")

    (options, args) = parser.parse_args()

    config = ConfigParser.ConfigParser()
    config.readfp(open(options.configfile))
    server = config.get('core', 'server')
    port = config.getint('core', 'port')
    user = User(config.get('core', 'user'), config.get('core', 'password'))

    if options.format is not None and options.format in ("nessus.v2", "pdf", "html", "csv"):
        fmt = options.format

    vid = None
    name = "CGI scanning test"
    nessus = Nessus(server, port)
    if nessus.login(user):
        print "[+] Successfully logged in."
        p = Policy()
        p.name = name
        if nessus.create_policy(p):
            print "[+] Policy successfully created."
            nessus.load_policies()
            for policy in nessus.policies:
                if policy.name == name:
                    nessus.get_policy_preferences(policy)
                    for preference in policy.preferences:
                        if preference.name == "Web Application Tests Settings":
                            for value in preference.values:
                                if value.name == "Enable web applications tests":
                                    vid = value.id
            if vid is not None:
                p.settings = {
                    "preferences.Web+Application+Tests+Settings.%d" % vid: "yes"
                }
                if nessus.update_policy(p):
                    print "[+] Policy settings successfully updated (Web Application Tests Settings)."
                else:
                    print "[!] An error occured when updating policy settings (Web Application Tests Settings)."
        else:
            print "[!] An error occured while creating the policy."
        if nessus.logout():
            print "[+] Successfully logged out."