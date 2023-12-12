#!/usr/bin/python3
"""
Shared classes and functions
"""
__author__ = "Enrico Tedeschi"
__copyright__ = "Copyright 2018, Arctic University of Norway"
__email__ = "enrico.tedeschi@uit.no"

import socket
from Crypto.Cipher import AES
import pickle

HOST = socket.gethostbyname('localhost')
PORT = 8300
# RESPONSES STATUS CODES:
OK = "200 OK"
CREATED = "201 Created"
ACCEPTED = "202 Accepted"
NO_CONTENT = "204 No Content"
NOTFOUND = "404 NOT FOUND"
TIME = 2

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


class Verifier:
    """
    its purpose is to verify the AES key
    """
    def __init__(self, nonce, ciphertext, tag, key=''):
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.tag = tag
        self.key = key


def aes_encode(key, msg):
    """
    given a key, it ciphers a message
    :param key:
    :param msg: message to cipher
    :return:
    """
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(pickle.dumps(msg))
    return nonce, ciphertext, tag


def aes_decode(nonce, ciphertext, tag, key):
    """
    it decodes a ciphertext encoded with AES
    :param nonce:
    :param ciphertext:
    :param tag:
    :param key: without the key, the incoming triple is useless
    :return:
    """
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        print(Colors.WARNING + "The message is authentic!" + Colors.ENDC)
    except ValueError:
        print("Key incorrect or message corrupted!")
        plaintext = ""
    finally:
        return pickle.loads(plaintext)
