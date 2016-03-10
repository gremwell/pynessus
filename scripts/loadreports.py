from optparse import OptionParser

from pynessus.nessus import Nessus
from framework import Framework


class ReportLoader(Framework):

    def __init__(self, options):
        self.export_format = options.format if options.format else "nessus"
        self.encryption_password = options.password if options.password else None
        super(ReportLoader, self).__init__(options.configfile)


    def run(self):
        nessus = Nessus(self.config.get('core', 'server'), self.config.get('core', 'port'))
        user = nessus.User(self.config.get('core', 'user'), self.config.get('core', 'password'))
        if nessus.login(user):
            nessus.load_scans()
            self.info("Successfully logged in.")
            self.info("%d reports will be downloaded." % (len(nessus.scans)))
            for scan in nessus.scans:
                path = scan.download(fmt=self.export_format, password=self.encryption_password)
                self.info("Report downloaded to %s" % path)

            if nessus.logout():
                self.info("Successfully logged out.")

if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-f", dest='format', help="report file format", default="nessus")
    parser.add_option("-p", dest='password', help="encryption password for NessusDB format")
    parser.add_option("-c", dest='configfile', default='nessus.conf', help="configuration file to use")

    (options, args) = parser.parse_args()
    rl = ReportLoader(options)
    rl.run()