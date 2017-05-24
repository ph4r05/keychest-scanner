#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import logging
import time
import requests
import util
import datetime
import traceback
import base64

import scapy
from scapy.layers.ssl_tls import *

import socket

target = ('root.cz', 443)

# create tcp socket
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(target)

tls_ver = "TLS_1_2"

cl_hello = TLSClientHello(version=tls_ver)
cl_hello.cipher_suites = [
    TLSCipherSuite.RSA_WITH_AES_256_CBC_SHA256,
    TLSCipherSuite.RSA_WITH_AES_256_CBC_SHA,

    TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA,
    TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA256,

    TLSCipherSuite.RSA_WITH_3DES_EDE_CBC_SHA,

    TLSCipherSuite.DHE_RSA_WITH_AES_128_CBC_SHA,
    TLSCipherSuite.DHE_RSA_WITH_AES_256_CBC_SHA,
    TLSCipherSuite.DHE_RSA_WITH_AES_128_CBC_SHA256,
    TLSCipherSuite.DHE_RSA_WITH_AES_256_CBC_SHA256,

    TLSCipherSuite.DHE_DSS_WITH_AES_256_CBC_SHA,
    TLSCipherSuite.DHE_DSS_WITH_AES_256_CBC_SHA256,

    TLSCipherSuite.ECDHE_RSA_WITH_AES_128_CBC_SHA,
    TLSCipherSuite.ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    TLSCipherSuite.ECDHE_RSA_WITH_AES_256_CBC_SHA,
    TLSCipherSuite.ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    TLSCipherSuite.ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
]

cl_hello.extensions = [
    TLSExtension() /
    TLSExtServerNameIndication(server_names=[TLSServerName(data=target[0])])
]


p = TLSRecord(version=tls_ver)/TLSHandshake()/cl_hello
p.show()

s.sendall(str(p))
resp = s.recv(65536*4)

# rec = TLSRecord(resp)
rec = SSL(resp)

print "resp: %s" % repr(resp)
print rec.show()

print '-' * 80
for srec in rec.records:
    print srec.show()
    print ' .' * 80

#
# # TLS handshake - server hello
# sub = rec.payload
# print(sub.type)
# # print(sub.show())
#
# # Server hello
# hello = sub.payload
# print(hello.version)
# print(hello.cipher_suite)
# # print(hello.show())
#
# subhello = hello.payload
# # print(subhello.show())
#
# print(base64.b64encode(str(subhello.payload)))

s.close()




