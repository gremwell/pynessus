from optparse import OptionParser
from pynessus.nessus import Nessus
from pynessus.models.user import User
from framework import Framework


class CGIScan(Framework):

    def __init__(self, configfile):
        super(CGIScan, self).__init__(configfile)

    def run(self):

        vid = None
        name = "CGI scanning test"
        nessus = Nessus(self.config.get('core', 'server'), self.config.getint('core', 'port'))
        user = nessus.User(self.config.get('core', 'user'), self.config.get('core', 'password'))
        if nessus.login(user):
            self.info("Successfully logged in.")
            p = nessus.Policy()
            p.name = name
            if nessus.create_policy(p):
                self.alert("Policy successfully created.")
                nessus.load_policies()
                for policy in nessus.policies:
                    if policy.name == name:
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
                        self.alert("Policy settings successfully updated (Web Application Tests Settings).")
                    else:
                        self.error("An error occured when updating policy settings (Web Application Tests Settings).")
            else:
                self.error("An error occured while creating the policy.")
            if nessus.logout():
                self.info("Successfully logged out.")

if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-c", dest='configfile', default='nessus.conf', help="configuration file to use")
    (options, args) = parser.parse_args()

    c = CGIScan(options.configfile)
    c.run()
