# CryptSockets

A simple sockets modules that encrypts all traffic using RSA keys from the pycryptodome module.


## Examples:

Server:

```
from cryptsockets import server

Server = server()
print('listening')
client = Server.accept()
print('Client accepted...')
client.send('What is your name?')
print('message sent, awaiting response...')
print('message: %s' % client.recv())
```

Client:

```
from cryptsockets import client

Client = client('127.0.0.1')
print('connected')
print(Client.recv())
print('Sending...')
Client.send('Tom')
```

## Classes and Functions

`**function** generate(bits=2048)`
  This function generate a private, public keypair.
  The argument bits is the size of the RSA modulus, 2048 is the default.
  returns private key, public key in that order
`**class** server(ip='0.0.0.0', port=1699, public=None, private=None, password=None)`
  This is the server class
  The ip arguement is the ip on which the server should bind to
  The port is used for binding as well
  public and private are the public and private keys repectively, can be left blank for new ones to be generated, can be the location of a file containing the key, or just the key, all must be in base64 format
  password, this is for if you are importing a private key that has a password
