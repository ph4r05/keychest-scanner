#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64
import hmac
import json
import logging
from hashlib import sha256

import phpserialize
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from . import util

logger = logging.getLogger(__name__)


def verify_mac(app_key, js):
    """
    MAC verification of the encrypter
    :param app_key:
    :param js:
    :return:
    """
    hmac_obj = hmac.new(app_key, util.to_bytes(js['iv'] + js['value']), sha256)
    comp_hmac = hmac_obj.hexdigest()

    if not hmac.compare_digest(util.to_bytes(comp_hmac), util.to_bytes(js['mac'])):
        raise ValueError('HMAC is invalid')


def decrypt_field(app_key, field, unserialize=True):
    """
    Decrypts DB encrypted field.
    Used for SSH keys.
    Implements Encrypter from Laravel

    :param app_key:
    :param field:
    :param unserialize:
    :return:
    """
    js_base = json.loads(field)
    enc_scheme = util.defvalkey(js_base, 'scheme')

    if enc_scheme != 'base':
        raise ValueError('Unknown encryption scheme: %s' % enc_scheme)

    payload = base64.b64decode(js_base['val'])
    js = json.loads(payload)

    if 'iv' not in js or 'mac' not in js or 'value' not in js:
        raise ValueError('Payload invalid - missing fields')

    verify_mac(app_key, js)
    iv = base64.b64decode(util.to_bytes(js['iv']))
    value = base64.b64decode(util.to_bytes(js['value']))

    # Here we will decrypt the value. If we are able to successfully decrypt it
    # we will then unserialize it and return it out to the caller. If we are
    # unable to decrypt this value we will throw out an exception message.
    decryptor = Cipher(
        algorithms.AES(app_key),
        modes.CBC(iv),
        backend=default_backend()
    ).decryptor()

    decrypted = decryptor.update(value) + decryptor.finalize()
    if unserialize:
        decrypted = phpserialize.loads(util.to_bytes(decrypted))

    return decrypted


class Encryptor(object):
    """
    Laravel encryptor wrapper
    """
    def __init__(self, app_key):
        self.app_key = app_key

    def decrypt(self, field, unserialize=True):
        """
        Decrypt the laravel protected field
        :param field:
        :return:
        """
        return decrypt_field(self.app_key, field, unserialize=unserialize)

