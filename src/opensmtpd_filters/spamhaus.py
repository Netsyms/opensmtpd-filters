#!/usr/bin/python3

import argparse
import email
import re
import traceback
import sys

from spamhauslib import SpamhausChecker
from opensmtpd import FilterServer

sh = SpamhausChecker()

server = False

def start():
    global server
    parser = argparse.ArgumentParser(description='Spamhaus ZEN')
    parser.add_argument('hostname', nargs='?', default='localhost')
    args = parser.parse_args()

    server = FilterServer()
    server.register_handler('filter', 'connect', handle_connect)
    server.serve_forever()

def handle_connect(session, hostname, src):
    global server
    #print(hostname, src, file=sys.stderr)
    try:
        status = sh.check_ip(src)
        if status["status"] == '1':
            return "reject|550 5.7.1 Blocked: " + status["assessment"] + ": Your IP is on a blocklist. Visit " + status["url"]
        if hostname != "<unknown>":
            status = sh.check_domain(hostname)
            if status["status"] == '1':
                return "reject|550 5.7.1 Blocked: " + status["assessment"] + ": Your hostname is on a blocklist. Visit " + status["url"]
    except:
        server.log_exception()
    return "proceed"

if __name__ == "__main__":
    start()
