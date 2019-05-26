# CryptSockets

A simple sockets module that encrypts all traffic using RSA keys from the pycryptodome module.


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

#### *Function* `generate(bits=2048)`

   This function generates a private, public keypair.
  
   **parameters:**   
   * bits - size of the RSA modulus, 2048 is the default
  
   Returns: (private key, public key) in that order
   <hr>
   
#### *Function* `KeyIn(key, password=None)`

   This function simply takes an RSA key object and outputs it as base64
   
   **parameters:**
   * key - the key to be used
   * password - if specified the key will be encrypted with this password
   
   Returns: The original key as base64
   
   <hr>
   
#### *Function* `keyOut(key, password)`

   This function takes in a base64 key and outputs an RSA key object
   
   **parameters:**
   * key - the key to be used
   * password - used if the key was encrypted using a password
   
   Returns: an RSA key object

   <hr>
   
#### *Class* `server(ip='0.0.0.0', port=1699, public=None, private=None, password=None)`

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
   <hr>
   
#### *object* `clientObj(client, session, serverPriv)`

   This is the object that is returned when calling accept on the server.
   
   **parameters:**
   * client - this is the socket object used to send and receive to a client
   * session - this is the session key
   * serverPriv - this is the servers private key
   
   **methods:**
   * `send(message)` - send an encrypted message to the connected client
   * `sendfile(path, name)` - used to send a file to a client
   * `recv(bufsiz=2048)` - used to recieve from the client, returns either the data or a file object
   
#### *object* `fileObj(name, contents)`

   This is the object that is returned if a file is received form client/server. 
   
   **parameters:**
   * name - the name of the file
   * contents - the contents of the file
   
   **methods:**
   * `write(path)` - this is used to write the contents of the file to a file.
   *  `read()` - this just returns the contents of the file

#### *Class* `client(ip, port=1699, public=None, private=None, password=None)`

   This is the server class.
  
   **parameters:**
   * ip - the ip that the client should connect to
   * port - the port that the server will bind to, default is 1699
   * public - The public key of the server, can be file or key, if left blank a new one will be generated
   * private - same as public
   * password - only relevant if you are importing a key and it is password locked

   **methods:**
   * `send()` - send encrypted data to the server
   * `sendfile(path, name)` - used to send a file.
   * `recv(bufsiz=2048)` - used to receive data/file from the server, iterated until all data is received and decrypted. If data is a file a file object will be returned.
   * `close()` - used to close the connection to the server
