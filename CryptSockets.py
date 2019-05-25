from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
import os
import re
import socket
import base64
from json import dumps, loads
from cryptography.fernet import Fernet

""" Functions for keys and encryption """


def encrypt(public, message):  # function to encrypt data
    cipher = PKCS1_OAEP.new(public)
    return base64.b64encode(cipher.encrypt(message.encode()))


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
    def __init__(self, ip='0.0.0.0', port=1699, public=None, private=None, password=None):
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
        self.s.bind((ip, port))
        self.s.listen(100)

    def close(self):
        self.s.close()

    def decrypt(self, message):  # A way to decrypt received data from the client, uses RSA
        cipher = PKCS1_OAEP.new(self.privateKey)
        try:
            return cipher.decrypt(base64.b64decode(message)).decode()
        except (ValueError, TypeError):
            return False

    def accept(self):  # Method to accept a client connection and return a client object
        client, addr = self.s.accept()
        packet = dumps({  # Makes a packet with the servers public key
            'public': self.publicKey
        }).encode()
        client.sendall(packet)  # send the data to the connected client
        data = self.decrypt(client.recv(2048).decode())  # decrypt received data, i.e the session key
        sessionKey = loads(data)['key']  # The client responds with the session key
        return clientObj(client, Fernet(sessionKey), self.privateKey)  # client object is returned


class clientObj:  # the client object
    def __init__(self, client, session, serverPriv):
        self.client = client
        self.sessionKey = session  # session key
        self.serverPriv = serverPriv

    def decrypt(self, message):  # this decrypt function uses Fernet for the session key
        try:
            return self.sessionKey.decrypt(message.encode()).decode()
        except InvalidToken:  # on decrypt error False will be returned
            return False

    def send(self, message):
        data = self.sessionKey.encrypt(message.encode()).decode() + ':end'  # encrypts data using session key
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
    def __init__(self, ip, port=1699):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((ip, port))
        self.serverPub = keyIn(loads(self.s.recv(2048).decode())['public'])
        session_key = Fernet.generate_key()
        self.sessionKey = Fernet(session_key)
        packet = dumps({  # exchanging keys with the server
            'key': session_key.decode()
        })
        enc = encrypt(self.serverPub, packet)
        self.s.sendall(enc)

    def decrypt(self, message):
        try:
            return self.sessionKey.decrypt(message.encode()).decode()
        except InvalidToken:
            return False

    def send(self, message):
        data = self.sessionKey.encrypt(message.encode()).decode() + ':end'
        self.s.sendall(data.encode())

    def close(self):
        self.s.close()

    def recv(self, bufsiz=2048):
        data = ''
        while True:
            data += self.s.recv(bufsiz).decode()
            if data.endswith(':end'):
                return self.decrypt(data[:-4])
