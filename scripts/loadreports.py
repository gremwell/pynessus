from optparse import OptionParser

from pynessus.nessus import Nessus
from framework import Framework


class ReportLoader(Framework):

    def __init__(self, configfile):
        super(ReportLoader, self).__init__(configfile)

    def run(self):
        nessus = Nessus(self.config.get('core', 'server'), self.config.get('core', 'port'))
        user = nessus.User(self.config.get('core', 'user'), self.config.get('core', 'password'))
        if nessus.login(user):
            nessus.load_reports()
            self.info("Successfully logged in.")
            self.info("%d reports will be downloaded." % (len(nessus.reports)))
            for report in nessus.reports:
                path = report.download()
                self.info("Report downloaded to %s" % path)

            if nessus.logout():
                self.info("Successfully logged out.")

if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-f", dest='format', help="report file format", default="nessus.v2")
    parser.add_option("-c", dest='configfile', default='nessus.conf', help="configuration file to use")

    (options, args) = parser.parse_args()
    rl = ReportLoader(options.configfile)
    rl.run()