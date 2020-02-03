#!/usr/bin/python3

__author__ = "Enrico Tedeschi"
__copyright__ = "Copyright 2020, Arctic University of Norway"
__email__ = "enrico.tedeschi@uit.no"

import socket
import sys
import rsa
import pickle
from utils import Colors, PORT, MAX_SIZE, OK, NO_CONTENT, NOTFOUND, HOST, Verifier, aes_encode, aes_decode, TIME
import datetime
import time

AES_KEY = b'TheForceIsStrong'  # 16bit AES key


class Server:
    def __init__(self):
        self.serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # socket object
        self.public = ""  # public key
        self.private = ""  # private key
        self.public_client = ""
        self.aes = AES_KEY  # aes key
        self.clientsocket = None
        self.setup()
        self.state = 0  # state of communication, relevant just for visual understanding.

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
        # bind to the port
        self.serversocket.bind((HOST, PORT))
        print("Listening on: " + Colors.BOLD + HOST + ":" + str(PORT) + Colors.ENDC)
        print("... waiting for a connection", file=sys.stderr)
        # queue up to 5 requests
        self.serversocket.listen(5)
        self.clientsocket, addr = self.serversocket.accept()
        print(Colors.FAIL + "( " + str(self.state) + " ) " + Colors.ENDC +
              "Got a connection from " + Colors.WARNING + "%s" % str(addr) + Colors.ENDC)
        self.state += 1
        try:
            while True:
                # establish a connection
                data = self.clientsocket.recv(MAX_SIZE)
                if not data:
                    time.sleep(2)
                    pass
                else:
                    time.sleep(TIME)
                    msg = ""
                    code = ""
                    method, destination, message = solve_message(pickle.loads(data))
                    if method == "GET" and destination == "/setup":
                        # 1. receive client's public key
                        # 2. send back server's public key
                        self.public_client = message
                        print(Colors.FAIL + "( " + str(self.state) + " ) " + Colors.ENDC +
                              "got " + Colors.OKGREEN + "client public key" + Colors.ENDC)
                        self.state += 1
                        msg = self.public
                        code = OK
                    elif method == "GET" and destination == "/aes":
                        # 1. receive the request for AES key encrypted with server's public key
                        # 2. decrypt it with server's private
                        # 3. send its AES key
                        print(Colors.FAIL + "( " + str(self.state) + " ) " + Colors.ENDC +
                              "got request for " + Colors.OKGREEN + "AES symmetric key" + Colors.ENDC)
                        self.state += 1
                        msg = rsa.encrypt(self.aes, self.public_client)
                        code = OK
                    elif method == "GET" and destination == "/msg":
                        # 1. Receive the message
                        # 2. Decrypt it and read the message
                        v = pickle.loads(message)
                        path = aes_decode(v.nonce, v.ciphertext, v.tag, self.aes)
                        print(Colors.FAIL + "( " + str(self.state) + " ) " + Colors.ENDC +
                              "Got " + Colors.OKGREEN + "message request" + Colors.ENDC + " from the client in the"
                                                                                          "following path: "
                              + Colors.BOLD + path + Colors.ENDC)
                        self.state += 1
                        with open(path + 'nonce.txt', 'rb') as nonce_file:
                            nonce = nonce_file.read()
                        with open(path + 'ciphertext.txt', 'rb') as ciph_file:
                            ciphertext = ciph_file.read()
                        with open(path + 'tag.txt', 'rb') as tag_file:
                            tag = tag_file.read()
                        verifier = Verifier(nonce, ciphertext, tag)
                        msg = pickle.dumps(verifier)
                        code = OK
                    if code == OK:
                        to_send = response_format(msg, code)
                        self.clientsocket.sendall(pickle.dumps(to_send))
        finally:
            self.clientsocket.close()


def response_format(msg, status_code):
    """
    Create the message in the following format:
    HTTP/1.1 200 OK\nDate:<date>\nServer:<server>\nLast-Modified:<last modified> \
    \nContent-Length:<content length>\nContent-Type:<content type>\nConnection:<connection>\n\nJSON
    :param msg: message to send
    :param status_code:
    :return: the message in the correct format
    """
    response_dict = {}
    date = datetime.datetime.now()
    server = str(HOST) + ":" + str(PORT)
    content_length = len(pickle.dumps(msg))
    response_dict["HEADER"] = "HTTP/1.1 " + status_code + "\nDate:" + str(date) + "\nServer:" + server + \
                              "\nContent-Length:" + str(content_length)
    response_dict["BODY"] = msg
    return response_dict


def solve_message(msg):
    """
    GET /messages HTTP/1.1
    Host:localhost

    POST /messages HTTP/1.1
    From: enrico Tedeschi
    User-Agent: HTTPTool/1.1
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 32

    home=<home>&favorite+flavor=<files>


    PUT /messages HTTP/1.1
    From:Enrico Tedeschi
    User-Agent:Mozilla/4.0 (compatible; MSIE 5.23; Mac_PowerPC)
    Content-Type:application/x-www-form-urlencoded
    Content-Length:30

    id=3&message=ciao%20come%20va?


    DELETE /messages HTTP/1.1
    From:Enrico Tedeschi
    User-Agent:Mozilla/4.0 (compatible; MSIE 5.23; Mac_PowerPC)
    Content-Type:application/x-www-form-urlencoded
    Content-Length:4

    id=4

    recieve a str in HTTP/1.1 format. Read and parse it.
    :param msg: message coming from client
    :return: method and content
    """
    try:
        header = msg["HEADER"]
        split_str = header.split(" ", 2)
        method = split_str[0]
        destination = split_str[1]
        message = msg["BODY"]
        # content = re.sub(r"\r+", '\n', content)
    except Exception as e:
        print(e)
        method = "GET"
        destination = "/setup"
        message = ""
    return method, destination, message


if __name__ == "__main__":
    try:
        srv = Server()
        srv.run()
    except KeyboardInterrupt:
        srv.clientsocket.close()
        print(Colors.WARNING + "Shutting down ... " + Colors.ENDC)

