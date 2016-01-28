from optparse import OptionParser
import sys
from pynessus import Nessus
from framework import Framework


class Demo(Framework):

    def __init__(self, configfile):
        super(Demo, self).__init__(configfile)

    def run(self):
        nessus = Nessus(self.config.get('core', 'server'), self.config.getint('core', 'port'))
        user = nessus.User(self.config.get('core', 'user'), self.config.get('core', 'password'))
        if nessus.login(user):
            self.info("Successfully logged in, getting informations ...")
            nessus.load()
            self.info("SCANNERS")
            for scanner in nessus.scanners:
                self.alert("\t%s %s" % (scanner.id, scanner.name))
            self.info("AGENTS")
            for agent in nessus.agents:
                self.alert("\t%s %s" % (agent.id, agent.name))
            self.info("SCANS")
            for scan in nessus.scans:
                self.alert("\t%s - %s" % (scan.id, scan.name))
            self.info("POLICIES")
            for policy in nessus.policies:
                self.alert("\t%s - %s" % (policy.id, policy.name))
            self.info("SCHEDULES")
            for schedule in nessus.schedules:
                self.alert("\t%s - %s" % (schedule.id, schedule.name))
            self.info("USERS")
            for user in nessus.users:
                self.alert("\t%s" % user.name)
            self.info("TAGS")
            for tag in nessus.tags:
                self.alert("\t%s" % tag.name)
            if nessus.logout():
                self.info("Successfully logged out.")
        else:
            self.warning("Usage : %s host username password" % (sys.argv[0]))

if __name__ == "__main__":

    parser = OptionParser()
    parser.add_option("-c", dest='configfile', default='nessus.conf', help="configuration file to use")
    (options, args) = parser.parse_args()

    d = Demo(options.configfile)
    d.run()