import ConfigParser
from optparse import OptionParser
from pynessus.nessus import Nessus


if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-f", dest='format', help="report file format", default="nessus.v2")
    parser.add_option("-c", dest='configfile', default='nessus.conf', help="configuration file to use")

    (options, args) = parser.parse_args()

    config = ConfigParser.ConfigParser()
    config.readfp(open(options.configfile))
    server = config.get('core', 'server')
    port = config.getint('core', 'port')

    nessus = Nessus(server, port)
    user = nessus.User(config.get('core', 'user'), config.get('core', 'password'))
    if nessus.login(user):
        nessus.load_reports()
        print "[+] Successfully logged in."
        print "[+] %d reports will be downloaded." % (len(nessus.reports))
        for report in nessus.reports:
            path = report.download()
            print "[+] Report downloaded to %s" % path

        if nessus.logout():
            print "[+] Successfully logged out."