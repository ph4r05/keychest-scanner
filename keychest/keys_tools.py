#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Keys utils
"""

from future.utils import iteritems
from past.builtins import basestring    # pip install future

import json
import argparse
import logging
import coloredlogs
import types
import base64
import hashlib
import sys
import os
import re
import binascii
import collections
import traceback
import requests
import math
import datetime
from math import ceil, log
from lxml import html
from pgpdump.data import AsciiData
from pgpdump.packet import SignaturePacket, PublicKeyPacket, PublicSubkeyPacket, UserIDPacket
from roca import detect


#            '%(asctime)s %(hostname)s %(name)s[%(process)d] %(levelname)s %(message)s'
LOG_FORMAT = '%(asctime)s [%(process)d] %(levelname)s %(message)s'
EMAIL_REGEX = re.compile('^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+$')

logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO, fmt=LOG_FORMAT)


def shorten_pre_json(data):
    """
    Shorten message being logged
    :param data:
    :return:
    """
    if isinstance(data, dict):
        return {k:shorten_pre_json(data[k]) for k in data}
    elif isinstance(data, list) or isinstance(data, tuple):
        return [shorten_pre_json(x) for x in data]
    elif isinstance(data, set):
        return [shorten_pre_json(x) for x in list(data)]
    elif isinstance(data, basestring):
        ln = len(data)
        return data if ln < 300 else '%s ...(%s)... %s' % (data[:150], ln - 300, data[-150:])
    else:
        return data


def reformat_pkcs7_pem(data):
    """
    Takes pkcs7 input file which may be DER encoded, PEM encoded with / without ascii armor header.
    :param data:
    :return: string - pem encoded pkcs7 file with ascii armor
    """
    is_pem = data.startswith('-----')
    if re.match(r'^[a-zA-Z0-9-\s+=/]+$', data):
        is_pem = True

    der = data
    if is_pem:
        data = re.sub(r'\s*-----\s*BEGIN\s+PKCS7\s*-----', '', data)
        data = re.sub(r'\s*-----\s*END\s+PKCS7\s*-----', '', data)
        der = base64.b64decode(data)

    pem_part = base64.b64encode(der)
    pem_part = '\n'.join(pem_part[pos:pos + 76] for pos in range(0, len(pem_part), 76))
    pem = '-----BEGIN PKCS7-----\n%s\n-----END PKCS7-----' % pem_part.strip()
    return pem


def process_pgp(data):
    """
    Processes / parses ASCII armored PGP key
    :param data:
    :return:
    """
    ret = []
    js_base = collections.OrderedDict()

    pgp_key_data = AsciiData(data)
    packets = list(pgp_key_data.packets())

    master_fprint = None
    master_key_id = None
    identities = []
    pubkeys = []
    sign_key_ids = []
    sig_cnt = 0
    for idx, packet in enumerate(packets):
        if isinstance(packet, PublicKeyPacket):
            master_fprint = packet.fingerprint
            master_key_id = detect.format_pgp_key(packet.key_id)
            pubkeys.append(packet)
        elif isinstance(packet, PublicSubkeyPacket):
            pubkeys.append(packet)
        elif isinstance(packet, UserIDPacket):
            identities.append(packet)
        elif isinstance(packet, SignaturePacket):
            sign_key_ids.append(packet.key_id)
            sig_cnt += 1

    # Names / identities
    ids_arr = []
    identity = None
    for packet in identities:
        idjs = collections.OrderedDict()
        idjs['name'] = packet.user_name
        idjs['email'] = packet.user_email
        ids_arr.append(idjs)

        if identity is None:
            identity = '%s <%s>' % (packet.user_name, packet.user_email)

    js_base['type'] = 'pgp'
    js_base['master_fprint'] = master_fprint
    js_base['master_key_id'] = master_key_id
    js_base['identities'] = ids_arr
    js_base['signatures_count'] = sig_cnt
    js_base['packets_count'] = len(packets)
    js_base['keys_count'] = len(pubkeys)
    js_base['signature_keys'] = list(set(sign_key_ids))
    return js_base


def get_pgp_key(key_id, attempts=4, timeout=12, logger=None, **kwargs):
    """
    Simple PGP key getter - tries to fetch given key from the key server
    :param attempts:
    :param timeout:
    :param logger:
    :return:
    """
    for attempt in range(attempts):
        try:
            res = requests.get('https://pgp.mit.edu/pks/lookup?op=get&search=0x%s' % detect.format_pgp_key(key_id),
                               timeout=timeout)

            if math.floor(res.status_code / 100) != 2.0:
                res.raise_for_status()

            data = res.content
            if data is None:
                raise Exception('Empty response')

            tree = html.fromstring(data)
            txt = tree.xpath('//pre/text()')
            if len(txt) > 0:
                return txt[0].strip()

            return None

        except Exception as e:
            if attempt+1 >= attempts:
                raise


def get_pgp_ids_by_email(email, attempts=4, timeout=12, logger=None, **kwargs):
    """
    Contacts key server, attempts to download PGP key by the pgp id.
    :param email:
    :param attempts:
    :param timeout:
    :param logger:
    :return:
    """
    for attempt in range(attempts):
        try:
            res = requests.get('https://pgp.mit.edu/pks/lookup?op=index&search=%s' % email, timeout=timeout)
            if math.floor(res.status_code / 100) != 2.0:
                res.raise_for_status()

            data = res.content
            if data is None:
                raise Exception('Empty response')

            return pgp_parse_keys(data)

        except Exception as e:
            if attempt + 1 >= attempts:
                raise


def pgp_parse_keys(data):
    """
    Parses key IDs from the index PGP server page
    :param data:
    :return:
    """
    tree = html.fromstring(data)
    ahrefs = tree.xpath('//a')
    if ahrefs is None or len(ahrefs) == 0:
        return []

    key_ids = []
    for ahref in ahrefs:
        link = ahref.attrib['href']
        if 'op=get' not in link:
            continue

        match = re.search(r'search=([x0-9a-fA-F]+)', link)
        if match is not None:
            key_ids.append(match.group(1))
    return key_ids


def is_email_valid(email):
    """
    Very simple email validation
    :param email:
    :return:
    """

    if EMAIL_REGEX.match(email) is None:
        return False

    if '.' not in email.split('@')[1]:
        return False

    return True


def is_pgp_id(pgp):
    """
    Returns true if the input value is valid PGP handle (hex string)
    :param pgp:
    :return:
    """
    return re.match(r'^[0-9a-fA-F]{5,16}$', pgp) is not None


def flatdrop(test_result):
    """
    drop_none - drop_empty - flatten
    :param test_result:
    :return:
    """
    return detect.drop_none(detect.drop_empty(flatten(test_result)))


def flatten(iterable):
    """
    Non-recursive flatten.
    :param iterable:
    :return:
    """
    try:
        iterator, sentinel, stack = iter(iterable), object(), []
    except TypeError:
        yield iterable
        return

    while True:
        value = next(iterator, sentinel)
        if value is sentinel:
            if not stack:
                break
            iterator = stack.pop()
        elif isinstance(value, str):
            yield value
        else:
            try:
                new_iterator = iter(value)
            except TypeError:
                yield value
            else:
                stack.append(iterator)
                iterator = new_iterator

