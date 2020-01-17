#!/usr/bin/python3
"""
Shared classes and methods
"""
__author__ = "Enrico Tedeschi"
__copyright__ = "Copyright 2018, Arctic University of Norway"
__email__ = "enrico.tedeschi@uit.no"

import socket

HOST = socket.gethostbyname('localhost')
PORT = 8300
# RESPONSES STATUS CODES:
OK = "200 OK"
CREATED = "201 Created"
ACCEPTED = "202 Accepted"
NO_CONTENT = "204 No Content"
NOTFOUND = "404 NOT FOUND"

MESSAGE_FILE = "messages.json"
MAX_SIZE = 10000


class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
