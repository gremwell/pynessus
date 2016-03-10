import logging
from datetime import datetime
import ConfigParser
import sys


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