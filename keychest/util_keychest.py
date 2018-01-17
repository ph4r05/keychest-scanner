#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64
import collections
import hmac
import json
import logging
import os
from hashlib import sha256

import phpserialize
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
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


def compute_mac(app_key, iv, value):
    """
    MAC computation for the Laravel encryptor
    :param app_key:
    :param iv: base64 encoded iv
    :param value: base64 encoded value
    :return:
    """
    hmac_obj = hmac.new(app_key, util.to_bytes(iv + value), sha256)
    return hmac_obj.hexdigest()


def encrypt_field_aes_cbc(app_key, field, serialize=True):
    """
    Encrypts DB field
    :param app_key:
    :param field:
    :param serialize:
    :return:
    """
    if serialize:
        field = phpserialize.dumps(field, object_hook=util.php_obj_hook)
    field = util.to_bytes(field)

    iv = os.urandom(16)

    encryptor = Cipher(
        algorithms.AES(app_key),
        modes.CBC(iv),
        backend=default_backend()
    ).encryptor()

    padder = padding.PKCS7(128).padder()
    field_padded = padder.update(field) + padder.finalize()

    ciphertext = encryptor.update(field_padded) + encryptor.finalize()

    ciphertext_base = base64.b64encode(ciphertext)
    iv_base = base64.b64encode(iv)

    mac_hex = compute_mac(app_key, iv=iv_base, value=ciphertext_base)
    js = collections.OrderedDict()
    js['iv'] = iv_base
    js['value'] = ciphertext_base
    js['mac'] = mac_hex

    js_base = collections.OrderedDict()
    js_base['scheme'] = 'base'
    js_base['val'] = base64.b64encode(json.dumps(js))
    return json.dumps(js_base)


def decrypt_field_aes_cbc(app_key, field, unserialize=True):
    """
    Decrypts DB encrypted field.
    Used for SSH keys.
    Implements Encrypter from Laravel

    :param app_key:
    :param field:
    :param unserialize:
    :return:
    """
    js_base = json.loads(util.to_string(field))
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

    unpadder = padding.PKCS7(128).unpadder()
    decrypted_unpadded = unpadder.update(decrypted) + unpadder.finalize()

    if unserialize:
        decrypted_unpadded = phpserialize.loads(decrypted_unpadded)

    return decrypted_unpadded


class Encryptor(object):
    """
    Laravel encryptor wrapper
    """
    def __init__(self, app_key, cipher=None, **kwargs):
        self.app_key = app_key
        self.cipher = None

    def encrypt(self, field, serialize=True):
        """
        Encrypts a field for the Laravel encrypter
        :param field:
        :param serialize:
        :return:
        """
        return encrypt_field_aes_cbc(self.app_key, field, serialize=serialize)

    def decrypt(self, field, unserialize=True):
        """
        Decrypt the Laravel protected field
        :param field:
        :return:
        """
        return decrypt_field_aes_cbc(self.app_key, field, unserialize=unserialize)

