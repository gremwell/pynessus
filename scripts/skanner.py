import time
import sys
from optparse import OptionParser
import os

from framework import Framework, Colors
from pynessus import Nessus


class Skanner(Framework):

    def __init__(self, configfile):
        super(Skanner, self).__init__(configfile)

    def run(self, options):

        try:
            nessus = Nessus(self.config.get('core', 'server'), self.config.get('core', 'port'))
            user = nessus.User(self.config.get('core', 'user'), self.config.get('core', 'password'))
            if options.scan_uuid is not None:
                found = False
                if nessus.login(user):
                    self.info("Successfully logged in.")
                    nessus.load_scans()
                    for scan in nessus.scans:
                        if scan.id == int(options.scan_uuid):
                            found = True
                            self.info("Found scan %s." % scan.uuid)
                            while scan.status != "completed" and scan.status != "canceled":
                                sys.stdout.write("%s[Status: %s]%s %0.2f%%\r" % (Colors.O, scan.status, Colors.N, scan.progress))
                                sys.stdout.flush()
                                time.sleep(5)
                            if scan.status == "completed":
                                path = scan.download()
                                if path is not None:
                                    self.info("Report downloaded to %s" % path)
                                else:
                                    raise Exception("An error occured while downloading report %s." % r.id)
                            else:
                                raise Exception("Scan has been canceled.")
                    if not found:
                        for scan in nessus.scans:
                            if scan.id == int(options.scan_uuid):
                                found = True
                                self.info("Found report for scan %s" % options.scan_uuid)
                                path = scan.download()
                                if path is not None:
                                    self.info("Report downloaded to %s" % path)
                                else:
                                    raise Exception("An error occured while downloading report %s." % report.id)
                    if not found:
                        raise Exception("Can't find scan identified by %s" % options.scan_uuid)
                else:
                    raise Exception("An error occured while logging you in.")
            else:
                if options.scan_name is None:
                    raise Exception("Scan name not provided. Aborting.")
                if options.policy_name is None:
                    raise Exception("Policy name not provided. Aborting.")

                if options.targets_file is not None:
                    with open(options.targets_file, "rb") as f:
                        targets = f.read().replace("\n", ",")
                elif options.targets is not None:
                    targets = options.targets
                else:
                    raise Exception("No provided targets. Aborting.")

                if nessus.login(user):
                    self.info("Successfully logged in.")
                    nessus.load_policies()
		    nessus.load_templates()
		    nessus.load_folders()
                    scan = nessus.Scan()
                    scan.name = options.scan_name
                    #scan.tag = nessus.folders[0]
                    # does the provided policy exists ?
                    for policy in nessus.policies:
                        if policy.name == options.policy_name:
                            scan.policy = policy
                    if scan.policy:
                        scan.custom_targets = targets
                        
			for folder in nessus.folders:
				if folder.name == "My Scans":
					scan.tag = folder
		        try:
				if scan.launch():
        	                    # scan launched, monitoring progress ...
                	            self.info("Scan %s has been launched, waiting for completion..." % scan.uuid)
                        	    while scan.status != "completed" and scan.status != "canceled":
	                                sys.stdout.write("%s[Status: %s]%s %0.2f%%\r" % (Colors.O, scan.status, Colors.N, scan.progress))
	                                sys.stdout.flush()
	                                time.sleep(5)
	                            if scan.status == "completed":
	                                path = scan.download()
	                                if path is not None:
	                                    self.info("Report downloaded to %s" % path)
	                                else:
        	                            raise Exception("An error occured while downloading report %s." % r.id)
	                            else:
        	                        raise Exception("Scan has been canceled.")
                	        else:
                        	    raise Exception("An error occured when launching the scan.")
			except Exception as e:
				print e.message
                    else:
                        raise Exception("Can't find the policy named %s. Aborting." % options.policy_name)
                    nessus.logout()
                else:
                    raise Exception("An error occured while logging you in.")
        except Exception as e:
            self.error(e.message)

if __name__ == "__main__":

    parser = OptionParser()
    parser.add_option("-i", dest='targets', help="targets ip addresses")
    parser.add_option("--iL", dest='targets_file', help="targets input file")
    parser.add_option("-n", dest='scan_name', help="scan name")
    parser.add_option("-p", dest='policy_name', help="policy_name")
    parser.add_option("-c", dest='configfile', help="configuration file to use")
    parser.add_option("-s", dest='scan_uuid', help="scan uuid to hook")
    (options, args) = parser.parse_args()

    skanner = Skanner(options.configfile)
    skanner.run(options)
