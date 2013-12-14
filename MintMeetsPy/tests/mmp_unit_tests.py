'''
Created on Dec 12, 2013

@author: pancho-villa
'''
import logging
import unittest
import sys
from MintMeetsPy import Session as m


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
        self.sesh = m(self.user, self.password, True)
        self.js_token = "12081017IDqZDKAxJjP6eS1224QJ5R2qz0wz9EJDuUDdrA"
        with open('raw.htm') as rh:
            self.html = rh.read()

    def tearDown(self):
        pass

    def testlogin(self):
        self.assertIn('javascript-token', self.html.lower())

    def testtoken_extraction(self):
        extracted_token = self.sesh.get_js_token(self.html)
        self.assertEqual(self.js_token, extracted_token)

    def testaccounts(self):
        pass

if __name__ == "__main__":
    unittest.main()
