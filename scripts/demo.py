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
            self.info("AGENT GROUPS")
            for group in nessus.agentgroups:
                self.alert("\t%s %s" % (group.id, group.name))
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
            self.info("MAIL SETTINGS")
            self.alert("\t%s" % nessus.mail.smtp_host)
            self.alert("\t%s" % nessus.mail.smtp_port)
            self.alert("\t%s" % nessus.mail.smtp_www_host)
            self.alert("\t%s" % nessus.mail.smtp_auth)
            self.alert("\t%s" % nessus.mail.smtp_user)
            self.alert("\t%s" % nessus.mail.smtp_pass)
            self.alert("\t%s" % nessus.mail.smtp_enc)
            self.info("PROXY SETTINGS")
            self.alert("\tProxy host: %s" % nessus.proxy.proxy)
            self.alert("\tProxy port: %s" % nessus.proxy.proxy_port)
            self.alert("\tProxy username: %s" % nessus.proxy.proxy_username)
            self.alert("\tProxy pass: %s" % nessus.proxy.proxy_password)
            self.alert("\tProxy user agent: %s" % nessus.proxy.user_agent)

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