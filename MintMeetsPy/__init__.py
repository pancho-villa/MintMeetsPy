import http.cookiejar
import gzip
import logging
import http.client
import urllib.parse
import json
from platform import platform
import signal
import argparse
from sys import stdout
import html
from urllib.error import URLError
import configparser
import os
import getpass


logger = logging.getLogger(__name__)


def signal_handler(signal, frame):
        print('You pressed Ctrl+C, quitting!')
        quit(0)

signal.signal(signal.SIGINT, signal_handler)

def confirm_pass():
    passwd = getpass.getpass()
    confirmed = getpass.getpass("Please enter again to confirm: ")
    if passwd != confirmed:
        confirm_pass()
    else:
        return passwd


class Session:
    """Class to authenticate and store a cookie for authentication"""

    def __init__(self, username=None, password=None, conf_file=None,
             use_proxy=False, proxy_host="127.0.0.1:8888", http_debug=False):
        """On creation it will instantiate object for reuse calling mint.com

        Defaults to not use a proxy. If use_proxy is True, then it takes a
        proxy host but defaults to Fiddler default install settings."""
        home = os.path.expanduser("~")
        default_conf = os.path.join(home, "mintmeetspy.ini")
        config = configparser.ConfigParser()
        if conf_file is None:
            default_
        if username is None and password is not None:
            self.username = input("Please enter your mint.com username: ")
            self.password = password
        elif username is not None and password is None:
            self.username = username
            self.password = confirm_pass()
        else:
            try:
                config.read(conf_file)
            except FileNotFoundError:
                logger.warning("No default config file found!")
                logger.info("Writing a default file to user home directory")
                self.username = input("Please enter your mint.com username: ")
                self.password = confirm_pass()
                config['DEFAULT'] = {'user': self.username, 'password':
                                     self.password}


        try:
            self.username = config['DEFAULT']['user']
            self.password = config['DEFAULT']['password']
        except KeyError as ke:
            logger.error("No value for %s" % ke)
            if ke == "user":
                self.username = input("Please enter your mint.com username: ")
            elif ke == "password":
                self.password = confirm_pass()

    

            
        if http_debug:
            http.client.HTTPSConnection.debuglevel = 1

        proxy = urllib.request.ProxyHandler({'http': proxy_host,
                                             'https': proxy_host})
        self.username = username
        ssl_context = None
        self.password = password
        self.login_url = "https://wwws.mint.com/loginUserSubmit.xevent"
        cj = http.cookiejar.CookieJar()
        cookie_handler = urllib.request.HTTPCookieProcessor(cj)
        logger = logging.getLogger(__name__ + ".Session")
        logger.debug("Using: {} as cookiejar".format(cj))
        '''Had to add this windows specific block to handle a bug in urllib2:
        http://bugs.python.org/issue11220
        '''
        if "windows" in platform().lower():
            import ssl
            ssl_context = urllib.request.HTTPSHandler(
                                  context=ssl.SSLContext(ssl.PROTOCOL_TLSv1))
        #end of urllib workaround
        if use_proxy and ssl_context:
            self.logger.debug("Using {} as a proxy".format(proxy_host))
            self.opener = urllib.request.build_opener(cookie_handler, proxy,
                                                      ssl_context)
        elif use_proxy and ssl_context is None:
            self.opener = urllib.request.build_opener(cookie_handler, proxy)
        elif not use_proxy and ssl_context:
            self.opener = urllib.request.build_opener(cookie_handler,
                                                      ssl_context)
        else:
            self.opener = urllib.request.build_opener(cookie_handler)

    def req(self, url, post_data=None, heads=None):
        """Makes all requests using the cookiejar to reuse the auth cookie.

        Takes in a URL, and optionally post body and or headers to append to
        the request. It will return the string representation of the remote
        resource decoded in UTF-8 format. Automatically handles gzip
        compression if the server returns it."""

        hdrs = {'Accept': "*/*",
                'Accept-Encoding': 'gzip,deflate,compress'}
        if post_data is None:
            req = urllib.request.Request(url, headers=hdrs)
        else:
            if isinstance(post_data, dict):
                self.logger.info("Coerced post_data into urlencoding")
                pd = urllib.parse.urlencode(post_data)
            else:
                pd = post_data
            req = urllib.request.Request(url, bytes(pd, 'utf-8'),
                                         headers=hdrs)
        if heads is not None:
            for k, v in heads.items():
                req.add_header(k, v)
        try:
            resp = self.opener.open(req)
        except urllib.error.HTTPError as he:
            self.logger.error("HTTP Error: %s" % he.code)
            self.logger.critical("%s" % he.reason)
            quit(1)
        except ConnectionRefusedError:
            self.logger.critical("Connection refused at {}".format(url))
            self.logger.warning("Did you set a proxy when there isn't one?")
            quit(1)
        except urllib.error.URLError as ue:
            if hasattr(ue, 'code') and hasattr(ue, 'reason'):
                self.logger.critical("HTTP connection failed due to: %s with %s" %
                                 ue.code, ue.reason)
            else:
                if hasattr(ue, 'reason'):
                    self.logger.critical("HTTP connection failed due to: %s" %
                                         ue.reason)

            self.logger.critical("Critical error connecting to %s" % url,
                                 exc_info=True)
            quit(1)

        if resp.headers.get('Content-Encoding') == 'gzip':
            return gzip.decompress(resp.read()).decode('utf-8')
        else:
            return resp.read().decode('utf-8')

    def login(self):
        """Logs into mint with the creds on instantiation of the session"""
        body = urllib.parse.urlencode({"username": self.username, "password":
                                       self.password, "task": "L",
                                       "nextPage": ""})
        return self.req(self.login_url, body)

    def get_js_token(self, html):
        """Extracts javascript-token from the html file for reuse

        Sets the attribute on the object so this shouldn't be called
        externally really ever, other than testing."""
        js_token_start = '<input id="javascript-token" name="token" ' + \
        'type="hidden" value="'
        js_token_startindex = html.find(js_token_start) + 63
        js_token_endindex = html.find('"', js_token_startindex + 1)
        js_token = html[js_token_startindex:js_token_endindex]
        self.logger.debug(js_token)
        self.js_token = js_token
        return self.js_token

    def initialize(self):
        """Tries to do the login for your and set all attributes

        I'm not sure if this works as expected right now, so ignore this"""
        self.get_js_token(self.login())
        return self

    def get_account_data(self):
        """Returns the list of all account info including balances"""
        #magic number? random number?
        request_id = "115485"  
        data = {"input": json.dumps([
            {"args": {
                "types": [
                    "BANK",
                    "CREDIT",
                    "INVESTMENT",
                    "LOAN",
                    "MORTGAGE",
                    "OTHER_PROPERTY",
                    "REAL_ESTATE",
                    "VEHICLE",
                    "UNCLASSIFIED"
                ]
            },
            "id": request_id,
            "service": "MintAccountService",
            "task": "getAccountsSorted"}
        ])}
        account_url = "https://wwws.mint.com/bundledServiceController." + \
        "xevent?token=" + self.js_token
        response = self.req(account_url, data)
        json_data = json.loads(response)['response']
        logger.debug(json_data)
        return json_data[request_id]['response']

    def get_transactions(self):
        """Returns a list of transactions"""
        trans_url = "https://wwws.mint.com/transaction.event"
        try:
            response = self.req(trans_url)
        except URLError as ue:
            logger.error("uh-oh, did it timeout?")
            quit()
        trans_node = '<input name="js-model-transactions" type="hidden" value="'
        trans_start = response.find(trans_node)
        trans_end = response.find('"', trans_start + len(trans_node) + 2)
        transactions = response[trans_start + len(trans_node):trans_end]
        payload = html.unescape(transactions)
        logger.debug(payload)
        return json.loads(payload)

if __name__ == "__main__":
    pass
