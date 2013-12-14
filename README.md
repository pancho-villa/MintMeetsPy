MintmeetPy
=======

MintmeetsPy(thon) is a screen-scraping API for Mint.com, shamelessly adapted from mintapi.

Requirements
===
Python 3

It was written solely in Py3k so if you want Python 2, you'll have to run 3to2.py or port it over. Pull requests gladly accepted, so long as you create  compatibility shims in the code base so there aren't duplicates of everything.

Usage
===

from Python
---
    from MintMeetsPy import Session as s
    u, p = "mintusername", "mydopeasspasswordyo!'
    sesh = s(u, p).initialize()
    account_json = sesh.get_account_data()
    account_names = [account['name'] for account in account_json]
    print(account_names)
    >>>['Dope Ass Blue Cash Preferred muthaf...', 'Legit TrueEarnings Card', 'Yo Checking', 'Yo Savings', 'checkit', 'Vacation Savings', 'CREDIT CARD']

---
from anywhere
---
    >>>python cli_interface.py email password (-v)
    >>>['Dope Ass Blue Cash Preferred muthaf...', 'Legit TrueEarnings Card', 'Yo Checking', 'Yo Savings', 'checkit', 'Vacation Savings', 'CREDIT CARD']