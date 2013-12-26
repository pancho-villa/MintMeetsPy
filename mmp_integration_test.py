'''
Created on Dec 13, 2013

@author: pancho-villa
'''
import logging
import unittest
import sys
import MintMeetsPy
import getpass
import os
from argparse import ArgumentParser
from argparse import RawDescriptionHelpFormatter
from configparser import ConfigParser


logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
fmt = '%(name)s - %(asctime)s - %(module)s-%(funcName)s - %(message)s'
formatter = logging.Formatter(fmt)
ch.setFormatter(formatter)
logger.addHandler(ch)
logger.debug("starting now!")

class MMPTest(unittest.TestCase):

    def setUp(self):
        self.logger = logging.getLogger(__name__)
        config_file = os.path.join(os.path.expanduser("~"),
                                        ".mintconfig.ini")
        self.config = MintMeetsPy.Configurator(conf=config_file)
        self.mint = MintMeetsPy.Mint()
        u, p = self.config.user, self.config.password
        self.mint.login(u, p)
        self.logger.debug("Logged in? {}".format(self.mint.logged_in))

    def tearDown(self):
        del self.mint

    def testdata(self):
        print(self.mint.data)
        

if __name__ == "__main__":
    unittest.main()
