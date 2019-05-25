from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
import os
import re
import socket
import base64
from json import dumps, loads

""" Functions for keys and encryption """


def encrypt(public, message):  # function to encrypt data
    cipher = PKCS1_OAEP.new(public)
    return base64.b64encode(cipher.encrypt(message.encode())).decode()


def generate(bits=2048):  # function to generate an rsa keypair
    p = RSA.generate(bits)
    return p, p.publickey()


def keyOut(key, password=None):  # A way of outputting a RSA key object in base64 format
    if password:
        return base64.b64encode(key.exportKey(format='DER', pkcs=8, protection='PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC', passphrase=password))
    else:
        return base64.b64encode(key.exportKey(format='DER')).decode()


def keyIn(key, password=None):  # takes in a key in base64 and turns it into an RSA key object
    if password:
        return RSA.import_key(base64.b64decode(key), passphrase=password)
    else:
        return RSA.import_key(base64.b64decode(key))


""" Classes """


class server:  # server class
    def __init__(self, port=1699, public=None, private=None, password=None):
        if not public and not private:  # If keys aren't defined they will be generated
            self.privateKey = RSA.generate(2048)
            self.publicKey = keyOut(self.privateKey.publickey())
        elif os.path.isfile(public) and os.path.isfile(private):  # checks if keys are in a file
            with open(public, 'r') as f:
                privateKey = f.read()
                self.privateKey = keyIn(privateKey, password)
            with open(public, 'r') as f:
                publicKey = f.read()
                self.publicKey = keyIn(publicKey)
        else:  # If keys are simply in base64 they will be stored
            self.privateKey = keyIn(private)
            self.publicKey = public
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind(('0.0.0.0', port))
        self.s.listen(100)

    def close(self):
        self.s.close()

    def accept(self):  # Method to accept a client connection and return a client object
        client, addr = self.s.accept()
        packet = dumps({  # Makes a packet with the servers public key
            'public': self.publicKey
        }).encode()
        client.sendall(packet)  # send the data to the connected client
        clientPub = loads(client.recv(2048).decode())['public']  # The client responds with their key which is loaded
        # and passed to the client object
        return clientObj(client, keyIn(clientPub), self.privateKey)


class clientObj:  # the client object
    def __init__(self, client, clientPub, clientPriv):
        self.client = client
        self.clientPub = clientPub
        self.clientPriv = clientPriv

    def decrypt(self, message):  # A way to decrypt received data from the client
        cipher = PKCS1_OAEP.new(self.clientPriv)
        try:
            return cipher.decrypt(base64.b64decode(message)).decode()
        except (ValueError, TypeError):
            return False

    def send(self, packet):  # Sends encrypted data to the connected client
        data = encrypt(self.clientPub, packet) + ':end'  # Specifies the end of the packet if length of data is large
        # than the buffer size
        self.client.sendall(data.encode())

    def close(self):  # closes a client connection
        self.client.close()

    def recv(self, bufsiz=2048):  # receives ALL data even if it's longer than the buffer size
        data = ''
        while True:
            data += self.client.recv(bufsiz).decode()
            if data.endswith(':end'):
                return self.decrypt(data[:-4])


class client:  # client class
    def __init__(self, ip, port=1699, public=None, private=None, password=None):
        if not public and not private:
            self.privateKey = RSA.generate(2048)
            self.publicKey = keyOut(self.privateKey.publickey())
        elif os.path.isfile(public) and os.path.isfile(private):
            with open(public, 'r') as f:
                privateKey = f.read()
                self.privateKey = keyIn(privateKey, password)
            with open(public, 'r') as f:
                publicKey = f.read()
                self.publicKey = keyIn(publicKey)
        else:
            self.privateKey = keyIn(private)
            self.publicKey = public

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((ip, port))
        packet = dumps({  # exchanging keys with the server
            'public': self.publicKey
        }).encode()
        self.s.sendall(packet)
        self.serverPub = keyIn(loads(self.s.recv(2048).decode())['public'])

    def decrypt(self, message):
        cipher = PKCS1_OAEP.new(self.privateKey)
        try:
            return cipher.decrypt(base64.b64decode(message)).decode()
        except (ValueError, TypeError):
            return False

    def send(self, message):
        data = encrypt(self.serverPub, message) + ':end'
        self.s.sendall(data.encode())

    def close(self):
        self.s.close()

    def recv(self, bufsiz=2048):
        data = ''
        while True:
            data += self.s.recv(bufsiz).decode()
            if data.endswith(':end'):
                return self.decrypt(data[:-4])
