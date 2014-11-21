import ConfigParser
from optparse import OptionParser
import time
import sys

from pynessus import Nessus

if __name__ == "__main__":

    parser = OptionParser()
    parser.add_option("-i", dest='targets', help="targets ip addresses")
    parser.add_option("-n", dest='scan_name', help="scan name")
    parser.add_option("-p", dest='policy_name', help="policy_name")
    parser.add_option("-c", dest='configfile', help="configuration file to use")
    (options, args) = parser.parse_args()

    config = ConfigParser.ConfigParser()
    config.readfp(open(options.configfile))
    server = config.get('core', 'server')
    port = config.getint('core', 'port')

    nessus = Nessus(server, port)
    user = nessus.User(config.get('core', 'user'), config.get('core', 'password'))
    if nessus.login(user):
        print "[+] Successfully logged in."
        nessus.load_policies()
        nessus.load_tags()
        scan = nessus.Scan()
        scan.name = options.scan_name
        scan.tag = nessus.tags[0]
        # does the provided policy exists ?
        for policy in nessus.policies:
            if policy.name == options.policy_name:
                scan.policy = policy
        if scan.policy:
            scan.custom_targets = options.targets
            if scan.launch():
                print "[+] Scan has been launched, waiting for completion..."
                progress = scan.progress()
                while progress < 100:
                    sys.stdout.write("[+] Current progress : %0.2f%%\r" % progress)
                    sys.stdout.flush()
                    progress = scan.progress()
                    time.sleep(5)
                print "[+] Scan completed."
                nessus.load_reports()
                for report in nessus.reports:
                    if report.id == scan.uuid:
                        path = report.download()
                        if path is not None:
                            print "[+] Scan report downloaded to %s." % path
        else:
            print "[!] Can't find the policy named %s. Aborting." % options.policy_name


    else:
        print "[!] An error occured while logging you in."
