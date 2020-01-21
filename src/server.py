#!/usr/bin/python3
# Server using socket

import socket
import sys
import rsa
import pickle
from utils import Colors, PORT, MAX_SIZE, OK, NO_CONTENT, NOTFOUND, HOST, Verifier, aes_encode, aes_decode
import datetime
import time


class Server:
    def __init__(self):
        self.serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # socket object
        self.public = ""  # public key
        self.private = ""  # private key
        self.public_client = ""
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
        # bind to the port
        self.serversocket.bind((HOST, PORT))
        print("Listening on: " + Colors.BOLD + HOST + ":" + str(PORT) + Colors.ENDC)
        print("... waiting for a connection", file=sys.stderr)
        # queue up to 5 requests
        self.serversocket.listen(5)
        self.clientsocket, addr = self.serversocket.accept()
        try:
            while True:
                # establish a connection
                data = self.clientsocket.recv(MAX_SIZE)
                if not data:
                    time.sleep(2)
                    pass
                else:
                    msg = ""
                    code = ""
                    print("Got a connection from " + Colors.WARNING + "%s" % str(addr) + Colors.ENDC)
                    method, destination, message = solve_message(pickle.loads(data))
                    if method == "GET" and destination == "/setup":
                        # 1. receive client's public key
                        # 2. send back server's public key
                        self.public_client = message
                        print("got " + Colors.OKGREEN + "client public key" + Colors.ENDC)
                        msg = self.public
                        code = OK
                    elif method == "GET" and destination == "/aes":
                        # 1. receive the AES key encrypted with server's public key
                        # 2. decrypt it with server's private
                        self.aes = rsa.decrypt(message, self.private)
                        print("got " + Colors.OKGREEN + "AES symmetric key" + Colors.ENDC)
                        msg = ""
                        code = OK
                    elif method == "GET" and destination == "/msg":
                        # 1. Receive the message
                        # 2. Decrypt it and read the message
                        v = pickle.loads(message)
                        plaintext = aes_decode(v.nonce, v.ciphertext, v.tag, self.aes)
                        print(plaintext)
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
    From: enrico tedeschi
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

