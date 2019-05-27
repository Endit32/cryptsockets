from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
import os
import re
import socket
import base64
from json import dumps, loads
import binascii
import cryptography
from cryptography.fernet import Fernet

""" Functions for keys and encryption """


def encrypt(public, message):  # function to encrypt data
    cipher = PKCS1_OAEP.new(public)
    return base64.b64encode(cipher.encrypt(message.encode()))  # returns bytes


def generate(bits=2048):  # function to generate an rsa keypair
    p = RSA.generate(bits)
    return p, p.publickey()


def keyOut(key, password=None):  # A way of outputting a RSA key object in base64 format
    if password:
        return base64.b64encode(key.exportKey(format='DER', pkcs=8, protection='PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC',
                                              passphrase=password)).decode()
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
        except (ValueError, TypeError) as e:
            raise Exception('Unable to decrypt data: %s' % e)

    def handshake(self, client):
        packet = dumps({  # Makes a packet with the servers public key
            'public': self.publicKey
        }).encode()
        client.sendall(packet)  # send the data to the connected client
        data = self.decrypt(client.recv(2048).decode())  # decrypt received data, i.e the session key
        packet = dumps({
            'type': 'session'
        }).encode()
        client.sendall(Fernet(loads(data)['key']).encrypt(packet))
        return loads(data)['key']  # The client responds with the session key

    def accept(self):  # Method to accept a client connection and return a client object
        client, addr = self.s.accept()
        sessionKey = self.handshake(client)
        return clientObj(client, Fernet(sessionKey), self.privateKey)  # client object is returned


class clientObj:  # the client object
    def __init__(self, client, session, serverPriv):
        self.client = client
        self.sessionKey = session  # session key
        self.serverPriv = serverPriv

    def decrypt(self, message):  # this decrypt function uses Fernet for the session key
        try:
            return self.sessionKey.decrypt(message.encode()).decode()
        except cryptography.fernet.InvalidToken as e:  # on decrypt error False will be returned
            raise Exception('Unable to decrypt data: %s' %e)

    def send(self, message):
        packet = dumps({
            'type': 'message',
            'data': message
        }).encode()
        data = self.sessionKey.encrypt(packet).decode() + ':end'
        self.client.sendall(data.encode())

    def sendfile(self, path):
        ex = re.search(r'\.(?!.*\.)', path)
        if ex:
            extension = path[ex.start():]
        else:
            extension = ''
        with open(path, 'rb') as f:
            contents = binascii.hexlify(f.read()).decode()
        packet = dumps({
            'type': 'file',
            'extension': extension,
            'contents': contents
        }).encode()
        try:
            data = self.sessionKey.encrypt(packet).decode() + ':end'
            self.client.sendall(data.encode())
        except BufferOverflow:
            raise Exception('File was too large')

    def close(self):  # closes a client connection
        self.client.close()

    def recv(self, bufsiz=2048):  # receives ALL data even if it's longer than the buffer size
        data = ''
        while True:
            data += self.client.recv(bufsiz).decode()
            if data.endswith(':end'):
                data = loads(self.decrypt(data[:-4]))
                if data['type'] == 'message':
                    return data['data']
                elif data['type'] == 'file':
                    return fileObj(data['extension'], data['contents'])


class fileObj:
    def __init__(self, extension, contents):
        self.ex = extension
        self.contents = binascii.unhexlify(contents)

    def make(self, path):
        with open(path + self.ex, 'wb') as f:
            f.write(self.contents)

    def read(self):
        return self.contents


class client:  # client class
    def __init__(self, ip, port=1699):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((ip, port))

        """ Handshake """

        self.serverPub = keyIn(loads(self.s.recv(2048).decode())['public'])
        session_key = Fernet.generate_key()
        self.sessionKey = Fernet(session_key)
        packet = dumps({  # exchanging keys with the server
            'key': session_key.decode()
        })
        enc = encrypt(self.serverPub, packet)
        self.s.sendall(enc)
        try:
            if loads(self.decrypt(self.s.recv(2048).decode()))['type'] != 'session':
                raise Exception('Unable to start session, may be a server issue')
        except cryptography.fernet.InvalidToken as e:
            raise Exception('Session data failed to decrypt, server/client key may be wrong: %s' % e)

    def decrypt(self, message):
        try:
            return self.sessionKey.decrypt(message.encode()).decode()
        except cryptography.fernet.InvalidToken as e:  # on decrypt error False will be returned
            raise Exception('Unable to decrypt data: %s' % e)

    def send(self, message):
        packet = dumps({
            'type': 'message',
            'data': message
        }).encode()
        data = self.sessionKey.encrypt(packet).decode() + ':end'
        self.s.sendall(data.encode())

    def sendfile(self, path):
        ex = re.search(r'\.(?!.*\.)', path)
        if ex:
            extension = path[ex.start():]
        else:
            extension = ''
        with open(path, 'rb') as f:
            contents = binascii.hexlify(f.read()).decode()
        packet = dumps({
            'type': 'file',
            'extension': extension,
            'contents': contents
        }).encode()
        try:
            data = self.sessionKey.encrypt(packet).decode() + ':end'
            self.s.sendall(data.encode())
        except BufferOverflow:
            raise Exception('File was too large')

    def close(self):
        self.s.close()

    def recv(self, bufsiz=2048):  # receives ALL data even if it's longer than the buffer size
        data = ''
        while True:
            data += self.s.recv(bufsiz).decode()
            if data.endswith(':end'):
                data = loads(self.decrypt(data[:-4]))
                if data['type'] == 'message':
                    return data['data']
                elif data['type'] == 'file':
                    return fileObj(data['extension'], data['contents'])
