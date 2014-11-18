import sys
from pynessus import Nessus, User

if __name__ == "__main__":

    if len(sys.argv) == 4:
        host = sys.argv[1]
        username = sys.argv[2]
        password = sys.argv[3]

        scanner = Nessus(host)
        if scanner.login(User(username, password)):
            print "[+] Successfully logged in, getting informations ..."
            scanner.load()
            print "###   SCANS  ###"
            for scan in scanner.scans:
                print "\t%s - %s" % (scan.id, scan.name)
            print "### POLICIES ###"
            for policy in scanner.policies:
                print "\t%s - %s" % (policy.id, policy.name)
            print "### SCHEDULES ###"
            for schedule in scanner.schedules:
                print "\t%s - %s" % (schedule.id, schedule.name)
            print "###   USERS ###"
            for user in scanner.users:
                print "\t%s" % user.name
            print "###   TAGS  ###"
            for tag in scanner.tags:
                print "\t%s" % tag.name
            if scanner.logout():
                print "[+] Successfully logged out."
    else:
        print "Usage : %s host username password" % (sys.argv[0])