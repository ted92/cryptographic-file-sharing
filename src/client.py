#!/usr/bin/python3

__author__ = "Enrico Tedeschi"
__copyright__ = "Copyright 2020, Arctic University of Norway"
__email__ = "enrico.tedeschi@uit.no"

from utils import Colors, MAX_SIZE, PORT, aes_decode
import socket
import sys
import rsa
import getopt
import re
import pickle
from utils import OK, Verifier, aes_encode, TIME


class Client:
    def __init__(self):
        self.clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_address = ("127.0.0.1", PORT)
        self.public = ""
        self.private = ""
        self.setup()
        self.aes = b''
        self.serverPublic = ""  # server public key
        self.clientsocket.connect(self.server_address)
        self.state = 0  # state of communication, relevant just for visual understanding.

    def connection_setup(self):
        """
        it sets up the connection with the server by exchanging public keys
        :return:
        """
        print("connection for setup with " + Colors.WARNING + "%s:%s"
              % self.server_address + Colors.ENDC, file=sys.stderr)
        # msg = self.clientsocket.recv(1024)
        # print(msg.decode('ascii'))
        to_send = form_request("GET", "setup", self.public)
        print(Colors.FAIL + "( " + str(self.state) + " ) " + Colors.ENDC + "sending "
              + Colors.OKGREEN + "public key " + Colors.ENDC + "to server")
        self.state += 1
        self.clientsocket.sendall(pickle.dumps(to_send))
        data = self.clientsocket.recv(MAX_SIZE)  # receive server public key
        code, self.serverPublic = receive(pickle.loads(data))
        # time.sleep(TIME)
        input()
        print(Colors.FAIL + "( " + str(self.state) + " ) " + Colors.ENDC +
              "got " + Colors.OKGREEN + "server public key" + Colors.ENDC)
        self.state += 1
        if code == OK:
            return True
        else:
            return False

    def request_symmetric(self):
        """
        send symmetric key only if server public key is already saved
        :return:
        """
        aes_ack = False  # acknowledgement for the symmetric aes key
        # the server public key must be saved already, otherwise keep trying to perform the setup
        while self.serverPublic == "":
            self.connection_setup()
        while not aes_ack:
            # encrypt the aes key with the server's public key
            to_send = form_request("GET", "aes", 'AES key?')
            print(Colors.FAIL + "( " + str(self.state) + " ) " + Colors.ENDC +
                  "requesting " + Colors.OKGREEN + "AES key " + Colors.ENDC + "to server")
            self.state += 1
            self.clientsocket.sendall(pickle.dumps(to_send))
            data = self.clientsocket.recv(MAX_SIZE)
            code, msg = receive(pickle.loads(data))
            # todo: decrypt with private key the aes key from the server
            self.aes = rsa.decrypt(msg, self.private)
            # time.sleep(TIME)
            if code == OK:
                print("AES key received from the server.")
                aes_ack = True

    def request_message(self, path='message/'):
        """
        send the plaintext.
        :var path: path of the file containing the message to send.
        :return:
        """
        ack = False
        while not ack:
            nonce, ciphertext, tag = aes_encode(self.aes, path)
            v = Verifier(nonce, ciphertext, tag)  # message to send to the server
            to_send = form_request("GET", "msg", pickle.dumps(v))
            print(Colors.FAIL + "( " + str(self.state) + " ) " + Colors.ENDC +
                  "requesting " + Colors.OKGREEN + "message " + Colors.ENDC + "to server")
            self.state += 1
            self.clientsocket.sendall(pickle.dumps(to_send))
            data = self.clientsocket.recv(MAX_SIZE)
            code, msg = receive(pickle.loads(data))
            v = pickle.loads(msg)
            print(aes_decode(v.nonce, v.ciphertext, v.tag, self.aes))
            # time.sleep(TIME)
            input()
            if code == OK:
                print("The message is recieved.")
                ack = True

    def close_connection(self):
        """
        close the open connection
        :return:
        """
        self.clientsocket.close()

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
        _, _ = getopt.getopt(argv, "p:", ["path="])
    except getopt.GetoptError:
        print("client.py -p <file_path>")
        sys.exit(2)
    c = Client()
    set_up = False
    while not set_up:
        set_up = c.connection_setup()
    # time.sleep(TIME)
    input()
    c.request_symmetric()  # request symmetric instead
    # time.sleep(TIME)
    input()
    c.request_message()  # receive message instead


if __name__ == "__main__":
    main(sys.argv[1:])
