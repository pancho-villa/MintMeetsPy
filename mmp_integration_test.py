'''
Created on Dec 13, 2013

@author: pancho-villa
'''
import logging
import unittest
import sys
from MintMeetsPy import Session as s
import getpass


logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
fmt = '%(name)s - %(asctime)s - %(module)s-%(funcName)s - %(message)s'
formatter = logging.Formatter(fmt)
ch.setFormatter(formatter)
logger.addHandler(ch)


def confirm_pass():
    passwd = getpass.getpass()
    confirmed = getpass.getpass("Please enter again to confirm: ")
    if passwd != confirmed:
        confirm_pass()
    else:
        return passwd


class MoneyTest(unittest.TestCase):

    def setUp(self):
        self.user = input("Please enter you Mint username: ")
        self.password = confirm_pass()
        self.sesh = s(self.user, self.password, True)

    def tearDown(self):
        del self.sesh

    def testaccounts(self):
        self.sesh.initialize()
        account_data = self.sesh.get_account_data()
        logger.debug(account_data)

if __name__ == "__main__":
    unittest.main()
