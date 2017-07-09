#!/usr/bin/env python
# -*- coding: utf-8 -*-

from past.builtins import basestring    # pip install future

import os
import re
import stat
import json
import hashlib
import base64
import collections
import datetime
import shutil
import calendar
import string
import random
import types
import decimal
import logging
import traceback
import pkg_resources
import phpserialize

import errno

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import ExtensionNotFound
from cryptography.x509.base import load_pem_x509_certificate, load_der_x509_certificate
from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.backends.openssl.backend import Backend as BackendOssl
from cryptography.hazmat.backends.openssl import decode_asn1
from cryptography import x509 as x509_c

import errors

import dateutil
import dateutil.parser


logger = logging.getLogger(__name__)


PAYLOAD_ENC_TYPE = 'AES-256-GCM-SHA256'


class AutoJSONEncoder(json.JSONEncoder):
    """
    JSON encoder trying to_json() first
    """
    DATE_FORMAT = "%Y-%m-%d"
    TIME_FORMAT = "%H:%M:%S"

    def default(self, obj):
        try:
            return obj.to_json()
        except AttributeError:
            return self.default_classic(obj)

    def default_classic(self, o):
        if isinstance(o, set):
            return list(o)
        elif isinstance(o, datetime.datetime):
            return o.strftime("%s %s" % (self.DATE_FORMAT, self.TIME_FORMAT))
        elif isinstance(o, datetime.date):
            return o.strftime(self.DATE_FORMAT)
        elif isinstance(o, datetime.time):
            return o.strftime(self.TIME_FORMAT)
        elif isinstance(o, decimal.Decimal):
            return str(o)
        else:
            return super(AutoJSONEncoder, self).default(o)


class CertCtOID(object):
    PRECERTIFICATE = ObjectIdentifier("1.3.6.1.4.1.11129.2.4.3")
    PRECERTIFICATE_CA = ObjectIdentifier("1.3.6.1.4.1.11129.2.4.4")


def php_obj_hook(obj):
    """
    Object hook for objects with defined php serialization support
    :param obj: 
    :return: 
    """
    try:
        return obj.to_php()
    except AttributeError as e:
        return '%s' % obj


def php_set_protected(obj, name, value):
    """
    Sets protected value for php
    :param obj: 
    :param name: 
    :param value: 
    :return: 
    """
    obj.__php_vars__["\x00*\x00%s" % name] = value
    return obj


def phpize(x):
    """
    Calls to_php if not already a phpobject
    :param x: 
    :return: 
    """
    if isinstance(x, phpserialize.phpobject):
        return x
    try:
        return x.to_php()
    except AttributeError:
        return x


def protect_payload(payload, config):
    """
    Builds a new JSON payload
    :param payload:
    :param config:
    :return:
    """
    js = json.dumps(payload)
    key = make_key(config.vpnauth_enc_password)

    iv, ciphertext, tag = encrypt(key, plaintext=js)

    ret = collections.OrderedDict()
    ret['enctype'] = PAYLOAD_ENC_TYPE
    ret['iv'] = base64.b64encode(iv)
    ret['tag'] = base64.b64encode(tag)
    ret['payload'] = base64.b64encode(ciphertext)
    return ret


def unprotect_payload(payload, config):
    """
    Processes protected request payload
    :param payload:
    :param config:
    :return:
    """
    if payload is None:
        raise ValueError('payload is None')
    if 'enctype' not in payload:
        raise ValueError('Enctype not in payload')
    if payload['enctype'] != PAYLOAD_ENC_TYPE:
        raise ValueError('Unknown payload protection: %s' % payload['enctype'])

    key = make_key(config.vpnauth_enc_password)
    iv = base64.b64decode(payload['iv'])
    tag = base64.b64decode(payload['tag'])
    ciphertext = base64.b64decode(payload['payload'])
    plaintext = decrypt(key=key, iv=iv, ciphertext=ciphertext, tag=tag)

    js = json.loads(plaintext)
    return js


def make_or_verify_dir(directory, mode=0o755, uid=0, strict=False):
    """Make sure directory exists with proper permissions.

    :param str directory: Path to a directory.
    :param int mode: Directory mode.
    :param int uid: Directory owner.
    :param bool strict: require directory to be owned by current user

    :raises .errors.Error: if a directory already exists,
        but has wrong permissions or owner

    :raises OSError: if invalid or inaccessible file names and
        paths, or other arguments that have the correct type,
        but are not accepted by the operating system.

    """
    try:
        os.makedirs(directory, mode)
    except OSError as exception:
        if exception.errno == errno.EEXIST:
            if strict and not check_permissions(directory, mode, uid):
                raise errors.Error(
                    "%s exists, but it should be owned by user %d with"
                    "permissions %s" % (directory, uid, oct(mode)))
        else:
            raise


def check_permissions(filepath, mode, uid=0):
    """Check file or directory permissions.

    :param str filepath: Path to the tested file (or directory).
    :param int mode: Expected file mode.
    :param int uid: Expected file owner.

    :returns: True if `mode` and `uid` match, False otherwise.
    :rtype: bool

    """
    file_stat = os.stat(filepath)
    return stat.S_IMODE(file_stat.st_mode) == mode and file_stat.st_uid == uid


def unique_file(path, mode=0o777):
    """Safely finds a unique file.

    :param str path: path/filename.ext
    :param int mode: File mode

    :returns: tuple of file object and file name

    """
    path, tail = os.path.split(path)
    filename, extension = os.path.splitext(tail)
    return _unique_file(
        path, filename_pat=(lambda count: "%s_%04d%s" % (filename, count, extension if not None else '')),
        count=0, mode=mode)


def _unique_file(path, filename_pat, count, mode):
    while True:
        current_path = os.path.join(path, filename_pat(count))
        try:
            return safe_open(current_path, chmod=mode),\
                os.path.abspath(current_path)
        except OSError as err:
            # "File exists," is okay, try a different name.
            if err.errno != errno.EEXIST:
                raise
        count += 1


def safe_open(path, mode="w", chmod=None, buffering=None):
    """Safely open a file.

    :param str path: Path to a file.
    :param str mode: Same os `mode` for `open`.
    :param int chmod: Same as `mode` for `os.open`, uses Python defaults
        if ``None``.
    :param int buffering: Same as `bufsize` for `os.fdopen`, uses Python
        defaults if ``None``.

    """
    # pylint: disable=star-args
    open_args = () if chmod is None else (chmod,)
    fdopen_args = () if buffering is None else (buffering,)
    return os.fdopen(
        os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, *open_args),
        mode, *fdopen_args)


def make_key(key):
    """
    Returns SHA256 key
    :param key:
    :return:
    """
    h = hashlib.sha256()
    h.update(key)
    return h.digest()


def encrypt(key, plaintext, associated_data=None):
    """
    Uses AES-GCM for encryption
    :param key:
    :param plaintext:
    :param associated_data:
    :return: iv, ciphertext, tag
    """

    # Generate a random 96-bit IV.
    iv = os.urandom(12)

    # Construct an AES-GCM Cipher object with the given key and a
    # randomly generated IV.
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    # associated_data will be authenticated but not encrypted,
    # it must also be passed in on decryption.
    if associated_data is not None:
        encryptor.authenticate_additional_data(associated_data)

    # Encrypt the plaintext and get the associated ciphertext.
    # GCM does not require padding.
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return (iv, ciphertext, encryptor.tag)


def decrypt(key, iv, ciphertext, tag, associated_data=None):
    """
    AES-GCM decryption
    :param key:
    :param associated_data:
    :param iv:
    :param ciphertext:
    :param tag:
    :return:
    """
    # Construct a Cipher object, with the key, iv, and additionally the
    # GCM tag used for authenticating the message.
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    # We put associated_data back in or the tag will fail to verify
    # when we finalize the decryptor.
    if associated_data is not None:
        decryptor.authenticate_additional_data(associated_data)

    # Decryption gets us the authenticated plaintext.
    # If the tag does not match an InvalidTag exception will be raised.
    return decryptor.update(ciphertext) + decryptor.finalize()


def silent_close(c):
    # noinspection PyBroadException
    try:
        if c is not None:
            c.close()
    except:
        pass


def unix_time(dt):
    if dt is None:
        return None
    cur = datetime.datetime.utcfromtimestamp(0)
    if dt.tzinfo is not None:
        cur.replace(tzinfo=dt.tzinfo)
    return (dt - cur).total_seconds()


def flush_file(data, filepath):
    """
    Flushes a file to the file e using move strategy
    :param data:
    :param filepath:
    :return:
    """
    abs_filepath = os.path.abspath(filepath)
    fw, tmp_filepath = unique_file(abs_filepath, mode=0o644)
    with fw:
        fw.write(data)
        fw.flush()

    shutil.move(tmp_filepath, abs_filepath)


def get_user_from_cname(cname):
    """
    Get user name from the cname.
    :param cname:
    :return:
    """
    if cname is None:
        return None
    return cname.split('/', 1)[0]


def is_utc_today(utc):
    """
    Returns true if the UTC is today
    :param utc: 
    :return: 
    """
    current_time = datetime.datetime.utcnow()
    day_start = current_time - datetime.timedelta(hours=current_time.hour, minutes=current_time.minute,
                                                  seconds=current_time.second)

    day_start_utc = unix_time(day_start)
    return (utc - day_start_utc) >= 0


def is_dbdate_today(dbdate):
    """
    Returns true if the database DateTime column is today
    :param dbdate: 
    :return: 
    """
    utc = calendar.timegm(dbdate.timetuple())
    return is_utc_today(utc)


def get_yesterday_date_end():
    """
    Returns yesterday midnight date time.
    :return: 
    """
    ct = datetime.datetime.utcnow()
    return datetime.datetime(year=ct.year, month=ct.month, day=ct.day, hour=23, minute=59, second=59) - \
           datetime.timedelta(days=1)


def get_7days_before_date_end():
    """
    Returns yesterday midnight date time.
    :return: 
    """
    ct = datetime.datetime.utcnow()
    return datetime.datetime(year=ct.year, month=ct.month, day=ct.day, hour=23, minute=59, second=59) - \
           datetime.timedelta(days=7)


def get_today_date_start():
    """
    Returns yesterday midnight date time.
    :return: 
    """
    ct = datetime.datetime.utcnow()
    return datetime.datetime(year=ct.year, month=ct.month, day=ct.day, hour=0, minute=0, second=0)


def random_nonce(length):
    """
    Generates a random password which consists of digits, lowercase and uppercase characters
    :param length:
    :return:
    """
    return ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits + "_") for _ in range(length))


def random_alphanum(length):
    """
    Generates a random password which consists of digits, lowercase and uppercase characters
    :param length:
    :return:
    """
    return ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(length))


def is_empty(x):
    """
    none or len(x) == 0
    :param x: 
    :return: 
    """
    return x is None or len(x) == 0


def strip(x):
    """
    Strips string x (if non empty) or each string in x if it is a list
    :param x:
    :return:
    """
    if x is None:
        return None
    if isinstance(x, types.ListType):
        return [y.strip() if y is not None else y for y in x]
    else:
        return x.strip()


def lower(x):
    """
    to lower or none
    :param x: 
    :return: 
    """
    if x is None:
        return None
    if isinstance(x, types.ListType):
        return [y.lower() if y is not None else y for y in x]
    else:
        return x.lower()


def defval(val, default=None):
    """
    Returns val if is not None, default instead
    :param val:
    :param default:
    :return:
    """
    return val if val is not None else default


def defvalkey(js, key, default=None, take_none=True):
    """
    Returns js[key] if set, otherwise default. Note js[key] can be None.
    :param js:
    :param key:
    :param default:
    :param take_none:
    :return:
    """
    if js is None:
        return default
    if key not in js:
        return default
    if js[key] is None and not take_none:
        return default
    return js[key]


def defvalkey_ic(js, key, default=None, take_none=True):
    """
    Returns js[key] if set, otherwise default. Note js[key] can be None.
    Keys are case insensitive
    :param js:
    :param key:
    :param default:
    :param take_none:
    :return:
    """
    if js is None:
        return default

    key_low = lower(key)
    for cur_key in js:
        ck = cur_key
        if isinstance(cur_key, basestring):
            ck = lower(cur_key)
        if ck == key_low:
            val = js[cur_key]
            if val is None and not take_none:
                return default
            else:
                return val
    return default


def defvalkeys(js, key, default=None):
    """
    Returns js[key] if set, otherwise default. Note js[key] can be None.
    Key is array of keys. js[k1][k2][k3]...

    :param js:
    :param key:
    :param default:
    :param take_none:
    :return:
    """
    if js is None:
        return default
    if not isinstance(key, types.ListType):
        key = [key]
        
    try:
        cur = js
        for ckey in key:
            cur = cur[ckey]
        return cur
    except:
        pass
    return default


def get_backend(backend=None):
    return default_backend() if backend is None else backend


def load_x509(data, backend=None):
    return load_pem_x509_certificate(data, get_backend(backend))


def load_x509_der(data, backend=None):
    return load_der_x509_certificate(data, get_backend(backend))


def get_cn(obj):
    """Accepts requests cert"""
    if obj is None:
        return None
    if 'subject' not in obj:
        return None

    sub = obj['subject'][0]
    for x in sub:
        if x[0] == 'commonName':
            return x[1]

    return None


def get_alts(obj):
    """Accepts requests cert"""
    if obj is None:
        return []
    if 'subjectAltName' not in obj:
        return []

    buf = []
    for x in obj['subjectAltName']:
        if x[0] == 'DNS':
            buf.append(x[1])

    return buf


def get_dn_part(subject, oid=None):
    if subject is None:
        return None
    if oid is None:
        raise ValueError('Disobey wont be tolerated')

    for sub in subject:
        if oid is not None and sub.oid == oid:
            return sub.value


def get_dn_string(subject):
    """
    Returns DN as a string
    :param subject: 
    :return: 
    """
    ret = []
    for attribute in subject:
        oid = attribute.oid
        dot = oid.dotted_string
        oid_name = oid._name
        val = attribute.value
        ret.append('%s: %s' % (oid_name, val))
    return ', '.join(ret)


def try_get_san(cert):
    """
    Tries to load SAN from the certificate
    :param cert: 
    :return: 
    """
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        if ext is not None:
            values = list(ext.value.get_values_for_type(x509_c.DNSName))
            return values
    except:
        pass

    return []


def try_is_ca(cert, quiet=True):
    """
    Tries to load SAN from the certificate
    :param cert: 
    :param quiet: 
    :return: 
    """
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        return ext.value.ca

    except ExtensionNotFound:
        return False

    except Exception as e:
        if not quiet:
            logger.error('Exception in getting CA rest. %s' % e)
            logger.debug(traceback.format_exc())

    return False


def try_is_precert(cert, quiet=True):
    """
    Tries to determine if certificate is a precertificate
    :param cert:
    :param quiet:
    :return:
    """
    try:
        ext = cert.extensions.get_extension_for_oid(CertCtOID.PRECERTIFICATE)
        return ext is not None

    except ExtensionNotFound:
        return False

    except Exception as e:
        if not quiet:
            logger.error('Exception in getting pre-cert. %s' % e)
            logger.debug(traceback.format_exc())

    return False


def try_is_precert_ca(cert, quiet=True):
    """
    Tries to determine if certificate is a precertificate
    :param cert:
    :param quiet:
    :return:
    """
    try:
        ext = cert.extensions.get_extension_for_oid(CertCtOID.PRECERTIFICATE_CA)
        return ext is not None

    except ExtensionNotFound:
        return False

    except Exception as e:
        if not quiet:
            logger.error('Exception in getting ca-pre-cert. %s' % e)
            logger.debug(traceback.format_exc())

    return False


def try_is_self_signed(cert, quiet=True):
    """
    Tries to determine if the certificate is self signed
    Currently implemented by comparing subject & issuer
    :param cert: 
    :param quiet: 
    :return: 
    """
    try:
        return cert.subject == cert.issuer

    except Exception as e:
        if not quiet:
            logger.error('Exception in self-signed check. %s' % e)
            logger.debug(traceback.format_exc())

    return None


def try_get_cname(cert):
    """
    Cname
    :param cert: 
    :return: 
    """
    try:
        return get_dn_part(cert.subject, NameOID.COMMON_NAME)
    except:
        pass
    return None


def try_parse_timestamp(x):
    """
    Tries to parse timestamp
    :param str: 
    :return: 
    """
    try:
        return dateutil.parser.parse(x)
    except:
        pass
    return None


def try_get_fprint_sha1(x):
    """
    Makes SHA1 fingerprint
    :param x: 
    :return: 
    """
    try:
        return base64.b16encode(x.fingerprint(hashes.SHA1()))
    except:
        pass
    return None


def try_get_fprint_sha256(x):
    """
    Makes SHA1 fingerprint
    :param x: 
    :return: 
    """
    try:
        return base64.b16encode(x.fingerprint(hashes.SHA256()))
    except:
        pass
    return None


def monkey_patch_asn1_time():
    """
    Monkey-patching of the date time parsing
    :return: 
    """
    def _parse_asn1_generalized_time(self, generalized_time):
        time = self._asn1_string_to_ascii(
            self._ffi.cast("ASN1_STRING *", generalized_time)
        )
        try:
            return datetime.datetime.strptime(time, "%Y%m%d%H%M%SZ")
        except Exception as e:
            logger.debug('Parsing ASN.1 date with standard format failed: %s, exc: %s' % (time, e))
            return dateutil.parser.parse(time)

    BackendOssl._parse_asn1_generalized_time = _parse_asn1_generalized_time

    def _parse_asn1_generalized_time(backend, generalized_time):
        time = decode_asn1._asn1_string_to_ascii(
            backend, backend._ffi.cast("ASN1_STRING *", generalized_time)
        )
        try:
            return datetime.datetime.strptime(time, "%Y%m%d%H%M%SZ")
        except Exception as e:
            logger.debug('Parsing ASN.1 date with standard format failed: %s, exc: %s' % (time, e))
            return dateutil.parser.parse(time)

    decode_asn1._parse_asn1_generalized_time = _parse_asn1_generalized_time


def utf8ize(x):
    """
    Converts to utf8 if non-empty
    :param x: 
    :return: 
    """
    if x is None:
        return None
    return x.encode('utf-8')


def dt_unaware(x):
    """
    Makes date time zone unaware
    :param x: 
    :return: 
    """
    if x is None:
        return None
    return x.replace(tzinfo=None)


def dt_norm(x):
    """
    Normalizes timestamp to UTC
    :param x: 
    :return: 
    """
    if x is None:
        return None

    tstamp = unix_time(x)
    return datetime.datetime.utcfromtimestamp(tstamp)


def drop_nones(lst):
    """
    Drop None elements from the list
    :param lst: 
    :return: 
    """
    return [x for x in lst if x is not None]


def load_roots():
    """
    Loads root certificates
    File downloaded from: https://curl.haxx.se/docs/caextract.html
    :return: 
    """

    resource_package = __name__
    resource_path = 'data/cacert.pem'
    return pkg_resources.resource_string(resource_package, resource_path)


def stable_uniq(x):
    """
    Stable unique filter - removes duplicates without sorting
    returns a new array, not modifying given.
    :param x: 
    :return: 
    """
    data = list(x)
    st = set(data)
    if len(st) == len(data):
        return x

    ret = []
    st = set()
    for x in data:
        if x in st:
            continue
        ret.append(x)
        st.add(x)
    return ret


def stip_quotes(x):
    """
    Strips surrounding quotes
    :param x:
    :return:
    """
    if x is None:
        return x

    m1 = re.match(r'^"(.+?)"$', x)
    if m1:
        return m1.group(1)

    m2 = re.match(r"^'(.+?)'$", x)
    if m2:
        return m2.group(1)

    return x


def try_sha1_pem(x):
    """
    Tries to compute certificate digest from the PEM
    :param x:
    :return:
    """
    try:
        bin_data = base64.b16decode(x, True)
        return hashlib.sha1(bin_data).hexdigest()

    except:
        return hashlib.sha1(x).hexdigest()


def try_load_json(x, **kwargs):
    """
    Tries to load JSON object
    :param x:
    :param kwargs:
    :return:
    """
    try:
        return json.loads(x, **kwargs)
    except Exception as e:
        pass
    return None


def first(x):
    """
    Gets the first element of the array, if array.
    Returns the input otherwise
    :param x:
    :return:
    """
    if x is None:
        return x

    if isinstance(x, types.ListType):
        if len(x) > 0:
            return x[0]
        return None
    return x


def try_list(x, take_string=False):
    """
    Tries to call list(x)
    :param x:
    :param take_string: if True list(str) is applied which splits string per characters. default is False
    :return:
    """
    if x is None:
        return []

    if not take_string and isinstance(x, basestring):
        return [x]

    try:
        return list(x)
    except:
        return [x]


def compact(arr):
    """
    Compacts array - removes all Nones
    :param arr:
    :return:
    """
    return [x for x in arr if x is not None]


def oid(x):
    """
    Returns object identifier if not already
    :param x:
    :return:
    """
    if not isinstance(x, ObjectIdentifier):
        return ObjectIdentifier(x)
    return x


def invert_map(x):
    """
    Inverts mapping
    :param x:
    :return:
    """
    return {x[k]: k for k in x}


def chunk(x, size=1):
    """
    Creates an array of elements split into groups the length of size.
    If array can't be split evenly, the final chunk will be the remaining elements.

    chunk(['a', 'b', 'c', 'd'], 2);
    // => [['a', 'b'], ['c', 'd']]

    chunk(['a', 'b', 'c', 'd'], 3);
    // => [['a', 'b', 'c'], ['d']]
    :param x:
    :param size:
    :return:
    """
    ret = []
    src = x
    while len(src) > 0:
        ret.append(src[:size])
        src = src[size:]
    return ret


