import ConfigParser
from optparse import OptionParser
from pynessus.nessus import Nessus
from pynessus.models.user import User


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

    nessus = Nessus(server, port)
    if nessus.login(user):
        nessus.load_reports()
        print "[+] Successfully logged in."
        print "[+] %d reports will be downloaded." % (len(nessus.reports))
        for report in nessus.reports:
            print "[+] Downloading report %s" % report.name
            nessus.load_report(report, fmt)
            path = report.save()
            print "[+] %s report downloaded to %s" % (report.name, path)

        if nessus.logout():
            print "[+] Successfully logged out."