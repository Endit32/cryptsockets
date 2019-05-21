from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pss
from Crypto.Cipher import PKCS1_OAEP
import os
import re
import socket
import base64
from threading import Thread
from json import dumps, loads


def keyOut(key, password=None):
    if password:
        return key.exportKey(format='DER', pkcs=8, protection='PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC',
                             passphrase=password)
    else:
        return base64.b64encode(key.exportKey(format='DER')).decode()


def keyIn(key, password=None):
    if password:
        return RSA.import_key(key, passphrase=password)
    else:
        return RSA.import_key(base64.b64decode(key))


class server:
    def __init__(self, port=1699, public=None, private=None, password=None):
        if not public and not private:
            self.privateKey = RSA.generate(2048)
            self.publicKey = keyOut(self.privateKey.publickey())
        else:
            if os.path.isfile(public) and os.path.isfile(private):
                with open(public, 'r') as f:
                    privateKey = f.read()
                    self.privateKey = keyIn(privateKey, password)
                with open(public, 'r') as f:
                    publicKey = f.read()
                    self.publicKey = keyIn(publicKey)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind(('0.0.0.0', port))
        self.s.listen(100)

    def encrypt(self, public, message):
        cipher = PKCS1_OAEP.new(public)
        return cipher.encrypt(message)

    def decrypt(self, message):
        cipher = PKCS1_OAEP.new(self.privateKey)
        return cipher.decrypt(message)

    def accept(self):
        client, addr = self.s.accept()
        packet = dumps({
            'public': self.publicKey
        }).encode()
        client.sendall(packet)
        clientPub = loads(client.recv(8192).decode())['public']
        return clientObj(client, keyIn(clientPub), self.privateKey, self.publicKey)


class clientObj:
    def __init__(self, client, clientPub, clientPriv, serverPub):
        self.client = client
        self.clientPub = clientPub
        self.clientPriv = clientPriv
        self.serverPub = serverPub

    def encrypt(self, public, message):
        cipher = PKCS1_OAEP.new(public)
        return cipher.encrypt(message.encode())

    def decrypt(self, message):
        cipher = PKCS1_OAEP.new(self.clientPriv)
        return cipher.decrypt(message)

    def send(self, packet):
        self.client.sendall(self.encrypt(self.clientPub, packet))

    def recv(self):
        data = ''
        while True:
            data += self.decrypt(self.client.recv(4096)).decode()
            if data.endswith(':end'):
                return data[:-4]


class client:
    def __init__(self, ip, port=1699, public=None, private=None, password=None):
        if not public and not private:
            self.privateKey = RSA.generate(2048)
            self.publicKey = keyOut(self.privateKey.publickey())
        else:
            if os.path.isfile(public) and os.path.isfile(private):
                with open(public, 'r') as f:
                    privateKey = f.read()
                    self.privateKey = keyIn(privateKey, password)
                with open(public, 'r') as f:
                    publicKey = f.read()
                    self.publicKey = keyIn(publicKey)

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((ip, port))
        packet = dumps({
            'public': self.publicKey
        }).encode()
        self.s.sendall(packet)
        self.serverPub = keyIn(loads(self.s.recv(8192).decode())['public'])

    def encrypt(self, public, message):
        cipher = PKCS1_OAEP.new(keyIn(public))
        return cipher.encrypt(message.encode())

    def decrypt(self, message):
        cipher = PKCS1_OAEP.new(self.privateKey)
        return cipher.decrypt(message)

    def send(self, message):
        data = self.encrypt(self.serverPub, message + ':end')
        self.s.sendall(data)

    def recv(self):
        data = ''
        while True:
            data += self.decrypt(self.s.recv(4096)).decode()
            if data.endswith(':end'):
                return data[:-4]

