import ConfigParser
from optparse import OptionParser
import sys
from pynessus import Nessus


if __name__ == "__main__":

    parser = OptionParser()
    parser.add_option("-c", dest='configfile', default='nessus.conf', help="configuration file to use")

    (options, args) = parser.parse_args()

    config = ConfigParser.ConfigParser()
    config.readfp(open(options.configfile))
    server = config.get('core', 'server')
    port = config.getint('core', 'port')

    nessus = Nessus(server, port)
    user = nessus.User(config.get('core', 'user'), config.get('core', 'password'))
    if nessus.login(user):
        print "[+] Successfully logged in, getting informations ..."
        nessus.load()
        print "###   SCANS  ###"
        for scan in nessus.scans:
            print "\t%s - %s" % (scan.id, scan.name)
        print "### POLICIES ###"
        for policy in nessus.policies:
            print "\t%s - %s" % (policy.id, policy.name)
        print "### SCHEDULES ###"
        for schedule in nessus.schedules:
            print "\t%s - %s" % (schedule.id, schedule.name)
        print "###   USERS ###"
        for user in nessus.users:
            print "\t%s" % user.name
        print "###   TAGS  ###"
        for tag in nessus.tags:
            print "\t%s" % tag.name
        if nessus.logout():
            print "[+] Successfully logged out."
    else:
        print "Usage : %s host username password" % (sys.argv[0])