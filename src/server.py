#!/usr/bin/python3
# Server using socket

import socket
import sys
import rsa

PORT = 8300


class Server:
    def __init__(self):
        self.serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # socket object
        self.public = ""  # public key
        self.private = ''  # private key
        self.aes = ""  # aes key
        self.clientsocket = None
        self.setup()

    def setup(self):
        """
        it sets up private and public keys
        :return:
        """
        self.public, self.private = rsa.newkeys(1024)

    def run(self):
        """
        it runs the server
        :return:
        """
        # get local machine name
        host = socket.gethostbyname('localhost')
        # bind to the port
        self.serversocket.bind((host, PORT))
        print("Listening on: " + Colors.BOLD + host + ":" + str(PORT) + Colors.ENDC)
        print("... waiting for a connection", file=sys.stderr)
        # queue up to 5 requests
        self.serversocket.listen(5)
        try:
            while True:
                # establish a connection
                self.clientsocket, addr = self.serversocket.accept()
                print("Got a connection from " + Colors.OKGREEN + "%s" % str(addr) + Colors.ENDC)
                msg = 'Thank you for connecting' + "\r\n"
                self.clientsocket.send(msg.encode('ascii'))
        finally:
            self.clientsocket.close()


class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


if __name__ == "__main__":
    srv = Server()
    srv.run()
