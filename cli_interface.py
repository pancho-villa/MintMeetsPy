#!/usr/bin/env python3
'''
Created on Dec 13, 2013

Simple wrapper for the MintMeetsPy module

Can call the get_account_data or the get_transactions method on the Session
object and returns a list of all account data or transactions respectively.

@author: pancho-villa
'''
import logging
import argparse
from sys import stdout
from MintMeetsPy import Session


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
                        description='CLI wrapper to get data out of mint.com')
    parser.add_argument('user', metavar="USERNAME", type=str,
                        help="""The Username for you Mint.com account
                        **not case-sensitive""",
                        default="yomama@yahoo.com")
    parser.add_argument('password', metavar="PASSWORD", type=str,
                        help="""The password for your Mint.com account
                        **case-sensitive""")
    parser.add_argument('accounts', nargs="?", default=argparse.SUPPRESS)
    parser.add_argument('--accounts', dest="acc", default=None)
    parser.add_argument('trans', nargs="?", default=argparse.SUPPRESS)
    parser.add_argument('--trans', dest="trans", default=None)
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Turns on verbose logging')

    args = parser.parse_args()
    u = args.user
    p = args.password
    logger = logging.getLogger()
    ch = logging.StreamHandler(stdout)
    fmt = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    formatter = logging.Formatter(fmt)
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        ch.setLevel(logging.DEBUG)
        logger.debug('Logging enabled!')
    else:
        logger.setLevel(logging.INFO)
        ch.setLevel(logging.INFO)
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    sesh = Session(u, p).initialize()
    if args.acc is not None:
        print([account['name'] for account in sesh.get_account_data()])
    if args.trans is not None:
        print([t for t in sesh.get_transactions()])