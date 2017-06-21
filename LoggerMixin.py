#!/usr/local/bin/python

import logging, logging.handlers
from os import system
import sys

class LoggerMixin():
    def __init__(self):
        rootlogger = logging.getLogger()
        #set overall level to debug, default is warning for root logger
        rootlogger.setLevel(logging.DEBUG)

        filelog = logging.handlers.TimedRotatingFileHandler(
            '../logs/fortressLog.log',
            when='midnight',
            interval=1,
        )
        filelog.setLevel(logging.DEBUG)
        fileformatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s')
        filelog.setFormatter(fileformatter)
        rootlogger.addHandler(filelog)

        #setup logging to console
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        consoleformatter = logging.Formatter(
            '%(asctime)-8s %(message)s',
            datefmt='%m-%d %H:%M:%S',
        )
        console.setFormatter(consoleformatter)
        rootlogger.addHandler(console)

    def _debug(self, *args):
        self._log(logging.DEBUG, *args)

    def _info(self, *args):
        print('\x1b[2K\r', end='') # clear existing line
        sys.stdout.flush()
        self._log(logging.INFO, *args)

    def _log(self, level, *args):
        logger = logging.getLogger(__name__)
        message = ' '.join(map(str, args))
        if (level == logging.DEBUG):
            logger.debug(message)
        elif (level == logging.INFO):
            logger.info(message)
