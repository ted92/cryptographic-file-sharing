#!/usr/bin/python3           # This is client.py file

from server import Colors
import socket
import sys
import rsa
import getopt


class Client:
    def __init__(self):
        self.clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_address = ("127.0.0.1", 8300)
        self.public = ""
        self.private = ""
        self.setup()
        self.serverPublic = ""  # server public key
        self.clientsocket.connect(self.server_address)

    def connection_setup(self):
        """
        it sets up the connection with the server by exchanging public keys,
        and then AES key for the communication
        :return:
        """
        print("connection for setup with " + Colors.OKGREEN + "%s:%s"
              % self.server_address + Colors.ENDC, file=sys.stderr)
        msg = self.clientsocket.recv(1024)
        print(msg.decode('ascii'))
        self.clientsocket.close()

    def setup(self):
        """
        it setups private and public keys
        :return:
        """
        self.public, self.private = rsa.newkeys(1024)


def main(argv):
    c = Client()
    c.connection_setup()
    try:
        opts, args = getopt.getopt(argv, "hp:", ["path="])
    except getopt.GetoptError:
        print("client.py -p <file_path>")
        sys.exit(2)


if __name__ == "__main__":
    main(sys.argv[1:])
