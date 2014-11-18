import sys
import os
import logging
import ConfigParser
import time
import socket
import xml.etree.ElementTree
from optparse import OptionParser
from logging.handlers import WatchedFileHandler
from datetime import datetime

from pynessus.nessus import Nessus
from pynessus.models.user import User
from pynessus.models.scan import Scan
from pynessus.models.report import Report


class NessusRunner:
    def __init__(self, configfile, scans):
        """
        :param configfile:
        :param scans:
        :return:
        """
        self.logformat = "%s %8s %s"
        self.scans_running = []  # Scans currently running.
        self.scans_complete = []  # Scans that have completed.
        self.scans = scans  # Scans that remain to be started.

        self.started = False  # Flag for telling when scanning has started.

        # Parse the configuration file to set everything up
        self.config = ConfigParser.ConfigParser()
        self.config.readfp(open(configfile))

        loglevels = {'debug': logging.DEBUG,
                     'info': logging.INFO,
                     'warning': logging.WARNING,
                     'error': logging.ERROR,
                     'critical': logging.CRITICAL}
        # Core settings
        self.logfile = self.config.get('core', 'logfile')
        self.loglevel = loglevels[self.config.get('core', 'loglevel')]

        # Setup some basic logging.
        self.logger = logging.getLogger('Nessus')
        self.logger.setLevel(self.loglevel)
        self.loghandler = WatchedFileHandler(self.logfile)
        self.logger.addHandler(self.loghandler)

        self.debug("CONF configfile = %s" % configfile)
        self.debug("Logger initiated; Logfile: %s, Loglevel: %s" % (self.logfile, self.loglevel))

        self.server = self.config.get('core', 'server')
        self.port = self.config.getint('core', 'port')
        self.user = User(self.config.get('core', 'user'), self.config.get('core', 'password'))
        self.report_path = self.config.get('core', 'report_path')
        self.limit = self.config.getint('core', 'limit')
        self.sleepmax = self.config.getint('core', 'sleepmax')
        self.sleepmin = self.config.getint('core', 'sleepmin')
        self.debug("PARSED scans: %s" % self.scans)

        try:
            self.info("Nessus scanner started.")
            self.scanner = Nessus(self.server, self.port)
            if self.scanner.login(self.user):
                self.info(
                    "Connected to Nessus server; authenticated to server '%s' as user '%s'" % (self.server, self.user))
                self.scanner.load()
            else:
                self.error("An error occured when logging into nessus server.")
        except socket.error as (errno, strerror):
            self.error(
                "Socket error encountered while connecting to Nessus server: %s. User: '%s', Server: '%s', Port: %s" % (
                strerror, self.user, self.server, self.port))

    def start(self):
        """
        Proxy for resume() really. Basically begins scanning with the current scanning list.
        """
        self.started = True

        if len(self.scans) > 1:
            self.info("Starting with multiple scans")
        else:
            self.info("Starting with a single scan")
        if self.scans_running is None:
            self.scans_running = []

        return self.resume()

    def stop(self):
        """
        We have a start() so we most certainly should have a stop(). This should prevent scans from being continued.
        """
        self.started = False

    def resume(self):
        """
        Basically gets scans going, observing the limit.
        """
        if self.started and len(self.scans) > 0 and len(self.scans_running) < self.limit:
            count = len(self.scans_running)
            for scan in self.scans:
                scan["target"] = NessusRunner.parse_nmap(scan["nmap_xml_file"])
                if self.scanner.upload_file(scan["nmap_xml_file"]):
                    self.info("%s has been uploaded." % (scan["nmap_xml_file"]))
                    for policy in self.scanner.policies:
                        if policy.name == scan["policy"]:
                            cp = policy
                    if cp is not None:
                        p = self.scanner.copy_policy(cp)
                        if p is None:
                            raise Exception("An error occured while copying policy.")
                        else:
                            p.name = "%s %s %s" % (scan["name"], scan["nmap_xml_file"], int(time.time()))
                            prefid = None
                            self.scanner.get_policy_preferences(p)
                            for preference in p.preferences:
                                if "Nmap (XML file importer)" in preference.name:
                                    for value in preference.values:
                                        prefid = value.id
                            if prefid is None:
                                raise Exception("Nmap plugin is either not installed or misconfigured.")
                            else:
                                settings = {
                                    "Filedata.Nmap+(%s)." % (p.name.replace(" ", "+")): os.path.basename(scan["nmap_xml_file"]),
                                    "preferences.Nmap+(%s).%d" % (p.name.replace(" ", "+"), int(prefid)): os.path.basename(scan["nmap_xml_file"]),
                                }
                                p.settings = settings
                                if not self.scanner.update_policy(p):
                                    raise Exception("An error occured while updating policy.")
                                else:
                                    currentscan = Scan()
                                    currentscan.name = scan["name"]
                                    currentscan.custom_targets = scan["target"]
                                    currentscan.policy = p
                                    currentscan.tag = self.scanner.tags[0]

                                    if self.scanner.create_scan(currentscan):
                                        self.info("Scan successfully started; Owner: '%s', Name: '%s'" %
                                                  (currentscan.owner.name, currentscan.name))
                                        self.scans_running.append(currentscan)
                                        self.scans.remove(scan)
                                        count += 1
                                        if count == self.limit:
                                            self.warning("Concurrent scan limit reached (currently set at %d)" % self.limit)
                                            self.warning("Will monitor scans and continue as possible")
                                            break
                                    else:
                                        self.error("Unable to start scan. Name: '%s', Target: '%s', Policy: '%s'" % (
                                                        currentscan.name, currentscan.custom_targets, currentscan.policy.name))
                    else:
                        self.error("That policy do not exist.")
                else:
                    self.error("An error occured while uploading file %s" % (scan["nmap_xml_file"]))
        return self.scans_running


    def iscomplete(self):
        """
        Check for the completion of of running scans. Also, if there are scans left to be run, resume and run them.
        """
        for scan in self.scans_running:
            if self.scanner.get_scan_progress(scan) >= 100:
                self.scans_complete.append(scan)
                self.scans_running.remove(scan)

        # Check to see if we're running under the limit and we have scans remaining.
        # If so, run more scans up to the limit and continue.

        if len(self.scans_running) < self.limit and len(self.scans) > 0 and self.started:
            self.info("We can run more scans, resuming")
            self.resume()
        elif len(self.scans_running) > 0:
            return False
        else:
            return True

    def report(self):
        """
        Report on currently completed scans.
        """
        for scan in self.scans_complete:
            report = Report()
            report.name = scan.uuid
            self.scanner.load_report(report)
            path = report.save("%s/%s.%s" % (self.report_path, report.name, report.format))
            if path is not None:
                self.info("Report for scan %s saved at %s" % (scan.name, path))

    @staticmethod
    def parse_nmap(nmap_xml_file):
        targets = []
        tree = xml.etree.ElementTree.parse(nmap_xml_file)
        root = tree.getroot()
        for i in root.iter("host"):
            targets.append(i.find("hostnames").find("hostname").get("name"))
            targets.append(i.find("address").get("addr"))
        return ",".join(targets)

    def close(self):
        """
        End it.
        """
        return self.scanner.logout()

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
    parser.add_option("-n", dest='name', default="No-name Auto Scan", help="name for the scan")
    parser.add_option("-p", dest='policy', help="policy (on server-side) to use in the scan")
    parser.add_option("-f", dest='infile', help="input file with multiple scans to run")
    parser.add_option("-c", dest='configfile', default='nessus.conf', help="configuration file to use")
    parser.add_option("-x", "--xml-nmap-file", dest="nmap_xml_file", help="")
    parser.add_option("--list-policies", dest="list_policies", help="")

    (options, args) = parser.parse_args()
    x = None

    if options.configfile is not None and options.list_policies is not None:
        x = NessusRunner(options.configfile, [])
        for policy in x.scanner.policies:
            print "%s - %s" % (policy.id, policy.name)
        sys.exit(0)
    if options.configfile is not None and (options.infile is not None or options.nmap_xml_file is not None):
        if options.infile is not None and options.nmap_xml_file is None:
            # Start with multiple scans.
            scans = []
            f = open(options.infile, "r")
            for line in f:
                scan = line.strip().split(',')
                scans.append({'name': scan[0], 'nmap_xml_file': scan[1], 'policy': scan[2]})
            x = NessusRunner(options.configfile, scans)
            scans = x.start()
        elif options.nmap_xml_file is not None and options.infile is None:
            # Start with a single scan.
            if options.name is not None and options.policy is not None:
                scan = [{'name': options.name, 'nmap_xml_file': options.nmap_xml_file, 'policy': options.policy}]
                x = NessusRunner(options.configfile, scan)
                scans = x.start()
            else:
                print "HARD ERROR: Incorrect usage.\n"
                parser.print_help()
                sys.exit(1)
        while not x.iscomplete():
            time.sleep(30)
        x.report()
        x.info("All done; closing")
        x.close()
        sys.exit(0)
    else:
        parser.print_help()
        sys.exit(0)
