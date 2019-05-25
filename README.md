# CryptSockets

A simple sockets modules that encrypts all traffic using RSA keys from the pycryptodome module.


## Examples:

Server:

```python
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

```python
from cryptsockets import client

Client = client('127.0.0.1')
print('connected')
print(Client.recv())
print('Sending...')
Client.send('Tom')
```

## Classes and Functions

#### **Function** `generate(bits=2048)`

   This function generates a private, public keypair.
  
   **parameters:**   
   * bits - size of the RSA modulus, 2048 is the default
  
   Returns: (private key, public key) in that order
   
  
#### **Class** `server(ip='0.0.0.0', port=1699, public=None, private=None, password=None)`

   This is the server class.
  
   **parameters:**
   * ip - the ip that the server will bind to, default is 0.0.0.0
   * port - the port that the server will bind to, default is 1699
   * public - The public key of the server, can be file or key, if left blank a new one will be generated
   * private - same as public
    * password - only relevant if you are importing a key and it is password locked

   **methods:**
   * `accept()` - accepts an incoming connection and returns a client object
   * `close()` - closes the socket.
   
  
#### **Class** `client(ip, port=1699, public=None, private=None, password=None)`

   This is the server class.
  
   **parameters:**
   * ip - the ip that the client should connect to
   * port - the port that the server will bind to, default is 1699
   * public - The public key of the server, can be file or key, if left blank a new one will be generated
   * private - same as public
   * password - only relevant if you are importing a key and it is password locked

   **methods:**
   * `send()` - send encrypted data to the server
   * `recv(bufsiz=2048)` - used to receive data from the server, iterated until all data is received and decrypted, returns the decrypted message or False if decryption fails
   * `close()` - used to close the connection to the server
