#!/usr/bin/python3

__author__ = "Enrico Tedeschi"
__copyright__ = "Copyright 2018, Arctic University of Norway"
__email__ = "enrico.tedeschi@uit.no"

from utils import Colors, MAX_SIZE, PORT
import socket
import sys
import rsa
import getopt
import re
import pickle


class Client:
    def __init__(self):
        self.clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_address = ("127.0.0.1", PORT)
        self.public = ""
        self.private = ""
        self.setup()
        self.serverPublic = ""  # server public key
        self.clientsocket.connect(self.server_address)

    def connection_setup(self):
        """
        it sets up the connection with the server by exchanging public keys
        :return:
        """
        print("connection for setup with " + Colors.OKGREEN + "%s:%s"
              % self.server_address + Colors.ENDC, file=sys.stderr)
        # msg = self.clientsocket.recv(1024)
        # print(msg.decode('ascii'))
        to_send = form_request("GET", "setup", self.public)
        print("sending %s" % to_send)
        self.clientsocket.sendall(pickle.dumps(to_send))
        data = self.clientsocket.recv(MAX_SIZE)  # receive server public key
        code, self.serverPublic = receive(pickle.loads(data))  # todo: write the server part and test it
        print("SERVER PUBLIC:)")
        print(self.serverPublic)
        self.clientsocket.close()  # todo: move this at the end

    def setup(self):
        """
        it setups private and public keys
        :return:
        """
        self.public, self.private = rsa.newkeys(1024)


def form_request(method, destination, message):
    """
    :param method: request type
    :param destination: purpose of the request
    :param message: message to send

    Create a HTTP/1.1 GET requests
    :param method:
    :param msg:
    :return:
    POST /messages HTTP/1.1
    From: enrico tedeschi
    User-Agent: HTTPTool/1.1
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 32

    home=<home>&favorite+flavor=<files>
    """
    request_dict = {}
    request_header = method + " /" + destination + " HTTP/1.1\nFrom:" + __author__ + "\n"
    user_agent = "Mozilla/4.0 (compatible; MSIE 5.23; Mac_PowerPC)"
    request_header = request_header + "User-Agent:" + user_agent + "\nContent-Type:application/x-www-form-urlencoded\n"
    content_length = len(pickle.dumps(message))
    request_header = request_header + "Content-Length:" + str(content_length) + "\n\n"
    request_dict["HEADER"] = request_header
    # === end header
    request_dict["BODY"] = message
    return request_dict


def receive(msg):
    """
    Get a message from Server with the error-OK code at the beginning using the HTTP/1.1 standard:
    HTTP/1.1 200 OK\nDate:<date>\nServer:<server>\nLast-Modified:<last modified> \
    \nContent-Length:<content length>\nContent-Type:<content type>\nConnection:<connection>\n\n<message>
    :param msg:
    :return: code and content
    """
    header = msg["HEADER"]
    content = msg["BODY"]
    start = header.split("\n")[0]
    code_obj = re.search('HTTP/1.1 (.*)', start)
    code = code_obj.group(1)
    return code, content


def main(argv):
    try:
        opts, args = getopt.getopt(argv, "p:", ["path="])
    except getopt.GetoptError:
        print("client.py -p <file_path>")
        sys.exit(2)
    c = Client()
    c.connection_setup()


if __name__ == "__main__":
    main(sys.argv[1:])
