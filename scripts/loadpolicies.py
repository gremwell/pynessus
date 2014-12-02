from optparse import OptionParser

from pynessus.nessus import Nessus
from framework import Framework


class PolicyLoader(Framework):

    def __init__(self, configfile):
        super(PolicyLoader, self).__init__(configfile)

    def run(self):
        nessus = Nessus(self.config.get('core', 'server'), self.config.getint('core', 'port'))
        user = nessus.User(self.config.get('core', 'user'), self.config.get('core', 'password'))
        if nessus.login(user):
            nessus.load_policies()
            self.info("Successfully logged in.")
            self.info("%d policies will be downloaded." %
                      (len([policy for policy in nessus.policies if policy.id > 0])))
            for policy in [policy for policy in nessus.policies if policy.id > 0]:
                path = policy.download()
                self.info("Policy downloaded to %s" % path)
            if nessus.logout():
                self.info("Successfully logged out.")
            else:
                self.error("An error occured while login you out.")
        else:
            self.error("An error occured while login you in.")

if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-c", dest='configfile', default='nessus.conf', help="configuration file to use")

    (options, args) = parser.parse_args()
    pl = PolicyLoader(options.configfile)
    pl.run()