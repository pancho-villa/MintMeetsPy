'''
Created on Dec 12, 2013

@author: pancho-villa
'''
import logging
import unittest
import sys
from MintMeetsPy import Mint as m


logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
fmt = '%(name)s - %(asctime)s - %(module)s-%(funcName)s - %(message)s'
formatter = logging.Formatter(fmt)
ch.setFormatter(formatter)
logger.addHandler(ch)


class MoneyTest(unittest.TestCase):

    def setUp(self):
        u, p = "testuser", "12345"
        self.sesh = m(u, p, True).initialize()
        self.js_token = "12081017IDqZDKAxJjP6eS1224QJ5R2qz0wz9EJDuUDdrA"
        with open('raw.htm') as rh:
            self.html = rh.read()

    def tearDown(self):
        del self.sesh

    def testlogin(self):
        self.assertIn('javascript-token', self.html.lower())

    def testtoken_extraction(self):
        extracted_token = self.sesh.get_js_token(self.html)
        self.assertEqual(self.js_token, extracted_token)

    def testget_account_data(self):
        account_data = self.sesh.get_account_data()
        self.assertEqual(type(account_data), list)

    def testget_transactions(self):
        transactions = self.sesh.get_transactions()
        self.assertEqual(type(transactions), list)

if __name__ == "__main__":
    unittest.main()
