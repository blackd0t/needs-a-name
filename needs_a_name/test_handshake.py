#! /usr/bin/python

'''
Experimental code for doing a V3 handshake.

Inflexible, buggy, error-prone, etc.  Just playing around.
'''

import base64
import ssl
import time
import calendar

from OpenSSL import crypto, SSL
import socket, sys, struct

circid = 0
command = 7
payload_len = 6

request = struct.pack('>H', circid)
request += struct.pack('>1B', command)
request += struct.pack('>H', payload_len)
# support version 3
request += struct.pack('>H', 3)
request += struct.pack('>H', 3)
request += struct.pack('>H', 3)

context = SSL.Context(SSL.SSLv23_METHOD)
ciphers = 'ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-CAMELLIA256-SHA:DHE-DSS-CAMELLIA256-SHA:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:ECDH-RSA-AES256-SHA:ECDH-ECDSA-AES256-SHA:CAMELLIA256-SHA:AES256-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-CAMELLIA128-SHA:DHE-DSS-CAMELLIA128-SHA:DHE-RSA-AES128-SHA256:DHE-DSS-AES128-SHA256:ECDH-RSA-RC4-SHA:ECDH-RSA-AES128-SHA:ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-AES128-SHA:SEED-SHA:CAMELLIA128-SHA:RC4-MD5:RC4-SHA:AES128-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:DHE-RSA-DES-CBC3-SHA:DHE-DSS-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-ECDSA-DES-CBC3-SHA:DES-CBC3-SHA'
context.set_cipher_list(ciphers)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssl_conn = SSL.Connection(context, s)
ssl_conn.connect(('198.58.118.200', 443))
ssl_conn.do_handshake()
ssl_conn.send(request)


### Get VERSIONS Cell
data = ssl_conn.read(2)
r_id = struct.unpack('>H', data)[0]
data = ssl_conn.read(1)
r_command = struct.unpack('>1B', data)[0]
data = ssl_conn.read(2)
r_length = int(struct.unpack('>H', data)[0])
data = ssl_conn.read(r_length)
r_payload = struct.unpack('>H', data)[0]

#print r_id
#print r_command
#print r_length
#print r_payload

### Read Variable Length CERTS Header ###
data = ssl_conn.read(2)
#print struct.unpack('>H', data)
data = ssl_conn.read(1)
#print struct.unpack('>1B', data)
data = ssl_conn.read(2)
#print struct.unpack('>H', data)
data = struct.unpack('>H', data)

### Read CERTS Cell Header ###
# num certs
ssl_conn.read(1)
# cert type
ssl_conn.read(1)
# cert length
data = struct.unpack('>H', ssl_conn.read(2))
# cert data
cert1 = ssl_conn.read(data[0])
cert1 = ssl.DER_cert_to_PEM_cert(cert1)
cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert1)
#print cert.get_extension_count()
#print cert.get_issuer()

## Cert 2
# read type
t = ssl_conn.read(1)
#print struct.unpack('>1B', t)
# clen
clen = int(struct.unpack('>H', ssl_conn.read(2))[0])
# read cert
cert2 = ssl_conn.read(clen)
cert2 = ssl.DER_cert_to_PEM_cert(cert2)
cert_x = crypto.load_certificate(crypto.FILETYPE_PEM, cert2)
#print cert.get_extension_count()
#print cert.get_issuer()


### Variable length AUTH_CHALLENGE header ###
# circid
ssl_conn.read(2)
# command
command = ssl_conn.read(1)
#print 'auth command: ' + str(struct.unpack('>1B', command)[0])
length = ssl_conn.read(2)
length = struct.unpack('>H', length)[0]
#print 'auth length: ' + str(length)
# read AUTH_CHALLENGE payload
#auth_challenge_payload = ssl_conn.read(length)
challenge = ssl_conn.read(32)
challenge = struct.unpack('>32s', challenge)
n_methods = ssl_conn.read(2)
n_methods = struct.unpack('>H', n_methods)[0]
methods = ssl_conn.read(n_methods*2)

### Read NETINFO fixed length header ###
circid = ssl_conn.read(2)
command = ssl_conn.read(1)
#print struct.unpack('>1B', command)
# 509 bytes left in NETINFO payload
#payload = ssl_conn.read(509)
#print len(payload)
timestamp = ssl_conn.read(4)
timestamp = struct.unpack('>i', timestamp)
### now a variable width Address Field ###
addr_type = ssl_conn.read(1)
addr_length = ssl_conn.read(1)
addr_length = struct.unpack('>1B', addr_length)[0]
#print addr_length
value = ssl_conn.read(4)

# number of addresses
num_addr = ssl_conn.read(1)
print 'num addresses: ' + str(struct.unpack('>1B', num_addr)[0])

# another variable Address Field
addr2_type = ssl_conn.read(1)
addr2_length = ssl_conn.read(1)
addr2_value = ssl_conn.read(struct.unpack('>1B', addr2_length)[0])
for j in xrange(len(addr2_value)):
    print struct.unpack('>1B', addr2_value[j])

# get zero padding
data = ssl_conn.read(492)


### send a NETINFO cell and we're done :)
# zero circid
netinfo = struct.pack('>H', 0)
# netinfo command is 8
netinfo += struct.pack('>1B', 8)
# at 509 bytes now
## get utc timestamp
timestamp = calendar.timegm(time.gmtime())
netinfo += struct.pack('>i', timestamp)
# pack variable length address field
netinfo += struct.pack('>1B', 4)
netinfo += struct.pack('>1B', 4)
netinfo += struct.pack('>1B', 198)
netinfo += struct.pack('>1B', 58)
netinfo += struct.pack('>1B', 118)
netinfo += struct.pack('>1B', 200)

# one more address
netinfo += struct.pack('>1B', 1)
# pack my address
netinfo += struct.pack('>1B', 1)
netinfo += struct.pack('>1B', 4)
netinfo += struct.pack('>1B', 173)
netinfo += struct.pack('>1B', 240)
netinfo += struct.pack('>1B', 197)
netinfo += struct.pack('>1B', 132)

# pad netinfo up to 512
while len(netinfo) < 512:
    netinfo += struct.pack('>1B', 0)
print len(netinfo)

# send netinfo to complete handshake :)
ssl_conn.send(netinfo)

data = ssl_conn.read(2048)
print data

ssl_conn.close()
