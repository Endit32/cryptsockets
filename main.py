from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pss
from Crypto.Cipher import PKCS1_OAEP
import os
import re
from threading import Thread
from json import dumps, loads

def keyOut(key, password=None):
    if password:
        return key.exportKey(format='DER', pkcs=8, protection='PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC',
                                              passphrase=password)
    else:
        return key.exportKey(format='DER')


def keyIn(key, password=None):
    if password:
        return RSA.import_key(key, passphrase=password)
    else:
        return RSA.import_key(key)



class server:
    def __init__(self, port=1699, public=None, private=None, password=None):
        if not public and not private:
            self.privateKey = RSA.generate(4096)
            self.publicKey = private.publickey()
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
        self.s.listen()

    def encrypt(self, public, message):
        cipher = PKCS1_OAEP.new(public)
        return cipher.encrypt(message)

    def decrypt(self, message):
        cipher = PKCS1_OAEP.new(self.privateKey)
        return cipher.decrypt(message)

    def recvall(self):
        data = None
        while True:
            data += sock.recv(4096)
            if re.search(':end$', data):
                return re.sub(':end$', "", data)

    def accept(self):
        client, addr = self.s.accept()
        packet=dumps({
            'public': self.publicKey
        }).encode()
        client.sendall(packet)
        clientPub = client.recv(8192)








class client:
    def __init__(self, ip, port, public=None, private=None, password=None):
        if not public and not private:
            self.privateKey = RSA.generate(4096)
            self.publicKey = private.publickey()
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
        serverPub = self.s.recv(8192)

    def encrypt(self, public, message):
        cipher = PKCS1_OAEP.new(public)
        return cipher.encrypt(message)

    def decrypt(self, message):
        cipher = PKCS1_OAEP.new(self.privateKey)
        return cipher.decrypt(message)


