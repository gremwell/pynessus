#!/usr/bin/env python
import time
import sys
import os
import ConfigParser
from datetime import datetime
from optparse import OptionParser
import logging

from pynessus import Nessus

class Colors(object):
    N = '\033[m'  # native
    R = '\033[31m'  # red
    G = '\033[32m'  # green
    O = '\033[33m'  # orange
    B = '\033[34m'  # blue


class Framework(object):

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

        self.logger.debug("CONF configfile = %s" % configfile)
        self.logger.debug("Logger initiated; Logfile: %s, Loglevel: %s" % (self.logfile, self.loglevel))

    def debug(self, msg):
        """
        @type   msg:    string
        @param  msg:    Debug message to be written to the log.
        """
        self.logger.debug(self.logformat % (datetime.now(), 'DEBUG', msg))

    def alert(self, msg):
        """
        @type   msg:    string
        @param  msg:    Alert message to be written to the log.
        """
        print('%s[*]%s %s' % (Colors.G, Colors.N, msg))
        self.logger.info(self.logformat % (datetime.now(), 'INFO', msg))

    def info(self, msg):
        """
        @type   msg:    string
        @param  msg:    Info message to be written to the log.
        """
        print('%s[*]%s %s' % (Colors.B, Colors.N, msg))
        self.logger.info(self.logformat % (datetime.now(), 'INFO', msg))

    def warning(self, msg):
        """
        @type   msg:    string
        @param  msg:    Warning message to be written to the log.
        """
        print('%s[#] %s%s' % (Colors.O, msg, Colors.N))
        self.logger.warning(self.logformat % (datetime.now(), 'WARNING', msg))

    def error(self, msg):
        """
        @type   msg:    string
        @param  msg:    Error message to be written to the log.
        """
        print('%s[!] %s%s' % (Colors.R, msg, Colors.N))
        self.logger.info(self.logformat % (datetime.now(), 'ERROR', msg))
        sys.exit(-1)

    def critical(self, msg):
        """
        @type   msg:    string
        @param  msg:    Critical message to be written to the log.
        """
        print('%s[!] %s%s' % (Colors.R, msg, Colors.N))
        self.logger.critical(self.logformat % (datetime.now(), 'CRITICAL', msg))

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
                            self.info("Found scan %s." % scan.name)
                            while scan.status != "completed" and scan.status != "canceled":
                                sys.stdout.write("%s[Status: %s]%s %d%%\r" % (Colors.O, scan.status, Colors.N, scan.progress))
                                sys.stdout.flush()
                                time.sleep(5)
                            if scan.status == "completed":
                                path = scan.download()
                                if path is not None:
                                    self.info("Report downloaded to %s" % path)
                                    print scan.information()
                                else:
                                    raise Exception("An error occured while downloading report %s." % r.id)
                            else:
                                raise Exception("Scan has been canceled.")
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
                    nessus.load_folders()
                    scan = nessus.Scan()
                    scan.name = options.scan_name
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
                                try:
                                    # scan launched, monitoring progress ...
                                    self.info("Scan %s has been launched, waiting for completion..." % scan.name)
                                    while scan.status != "completed" and scan.status != "canceled":
                                        sys.stdout.write("%s[Status: %s]%s %d%%\r" % (Colors.O, scan.status, Colors.N, scan.progress))
                                        sys.stdout.flush()
                                        time.sleep(5)
                                    if scan.status == "completed":
                                        path = scan.download()
                                        if path is not None:
                                            self.info("Report downloaded to %s" % path)
                                            print scan.information()
                                        else:
                                            raise Exception("An error occured while downloading report %s." % r.id)
                                    else:
                                        raise Exception("Scan has been canceled.")
                                except KeyboardInterrupt:
                                    self.warning("Aborting scan ...")
                                    if scan.stop():
                                        self.info("Scan successfully aborted.")
                                    else:
                                        self.error("An error occured while aborting the scan.")
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

    if options.configfile is None:
        parser.print_help()
    else:
        skanner = Skanner(options.configfile)
        skanner.run(options)
