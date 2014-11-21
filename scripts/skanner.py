import ConfigParser
from optparse import OptionParser
import time
import sys
import logging
from datetime import datetime

from pynessus import Nessus

class Skanner(object):

    def __init__(self, configfile):
        self.config = ConfigParser.ConfigParser()
        self.config.readfp(open(configfile))

        loglevels = {'debug': logging.DEBUG,
                     'info': logging.INFO,
                     'warning': logging.WARNING,
                     'error': logging.ERROR,
                     'critical': logging.CRITICAL}
        self.logformat = "%s %8s %s"
        # Core settings
        self.logfile = self.config.get('core', 'logfile')
        self.loglevel = loglevels[self.config.get('core', 'loglevel')]

        # Setup some basic logging.
        self.logger = logging.getLogger('Nessus')
        self.logger.setLevel(self.loglevel)
        self.logger.addHandler(logging.FileHandler(self.logfile))

        self.logger.debug("CONF configfile = %s" % options.configfile)
        self.logger.debug("Logger initiated; Logfile: %s, Loglevel: %s" % (self.logfile, self.loglevel))


    def run(self, options):

        if options.scan_name is None:
            self.error("Scan name not provided. Aborting.")
            return
        if options.policy_name is None:
            self.error("Policy name not provided. Aborting.")
            return

        if options.targets_file is not None:
            with open(options.targets_file, "rb") as f:
                targets = f.read().replace("\n", ",")
        elif options.targets is not None:
            targets = options.targets
        else:
            self.error("No provided targets. Aborting.")

        nessus = Nessus(self.config.get('core', 'server'), self.config.get('core', 'port'))
        user = nessus.User(self.config.get('core', 'user'), self.config.get('core', 'password'))
        if nessus.login(user):
            self.info("Successfully logged in.")
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
                scan.custom_targets = targets
                if scan.launch():
                    # scan launched, monitoring progress ...
                    self.info("Scan has been launched, waiting for completion...")
                    print "[+] Scan has been launched, waiting for completion..."
                    status, percentage = scan.progress()
                    while status == "running":
                        sys.stdout.write("[+] Current progress : %0.2f%%\r" % percentage)
                        sys.stdout.flush()
                        status, percentage = scan.progress()
                        time.sleep(5)
                    if scan.status == "completed":
                        r = nessus.Report()
                        r.id = scan.uuid
                        path = r.download()
                        if path is not None:
                            self.info("Report downloaded to %s" % path)
                        else:
                            self.error("An error occured while downloading report %s." % r.id)
                    else:
                        self.error("Can't download report because scan status is %s." % scan.status)
                else:
                    self.error("An error occured when launching the scan.")
            else:
                self.error("Can't find the policy named %s. Aborting." % options.policy_name)
            nessus.logout()
        else:
            self.error("[!] An error occured while logging you in.")


    def debug(self, msg):
        """
        @type   msg:    string
        @param  msg:    Debug message to be written to the log.
        """
        self.logger.debug(self.logformat % (datetime.now(), 'DEBUG', msg))

    def info(self, msg):
        """
        @type   msg:    string
        @param  msg:    Info message to be written to the log.
        """
        self.logger.info(self.logformat % (datetime.now(), 'INFO', msg))

    def warning(self, msg):
        """
        @type   msg:    string
        @param  msg:    Warning message to be written to the log.
        """
        self.logger.warning(self.logformat % (datetime.now(), 'WARNING', msg))

    def error(self, msg):
        """
        @type   msg:    string
        @param  msg:    Error message to be written to the log.
        """
        self.logger.info(self.logformat % (datetime.now(), 'ERROR', msg))

    def critical(self, msg):
        """
        @type   msg:    string
        @param  msg:    Critical message to be written to the log.
        """
        self.logger.critical(self.logformat % (datetime.now(), 'CRITICAL', msg))

if __name__ == "__main__":

    parser = OptionParser()
    parser.add_option("-i", dest='targets', help="targets ip addresses")
    parser.add_option("--iL", dest='targets_file', help="targets input file")
    parser.add_option("-n", dest='scan_name', help="scan name")
    parser.add_option("-p", dest='policy_name', help="policy_name")
    parser.add_option("-c", dest='configfile', help="configuration file to use")
    (options, args) = parser.parse_args()

    skanner = Skanner(options.configfile)
    skanner.run(options)
