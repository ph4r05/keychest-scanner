#!/usr/bin/env python
# -*- coding: utf-8 -*-

from past.builtins import basestring    # pip install future
from past.builtins import long

import os
import re
import stat
import json
import pwd
import grp
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
from cryptography.x509 import ExtensionNotFound, SubjectKeyIdentifier
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


def json_dumps(obj, **kwargs):
    """
    Uses auto encoder to serialize the object
    :param obj:
    :param kwargs:
    :return:
    """
    return json.dumps(obj, cls=AutoJSONEncoder, **kwargs)


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


def chown(path, user=None, group=None, follow_symlinks=False):
    """
    Changes the ownership of the path.
    https://docs.python.org/2/library/os.html

    :param path:
    :param user: string user name / numerical user id / None to leave as is
    :param group: string group name / numerical group id / None to leave as is
    :return:
    """
    if user is None and group is None:
        return

    # User resolve
    if user is None:
        uid = -1
    elif isinstance(user, types.IntType):
        uid = user
    else:
        uid = pwd.getpwnam(user).pw_uid

    # Group resolve
    if group is None:
        gid = -1
    elif isinstance(group, types.IntType):
        gid = group
    else:
        gid = grp.getgrnam(group).gr_gid
    os.chown(path, uid, gid)


def makedirs(path, mode=0o777):
    """
    Make dir if does not exist
    :param path:
    :param mode:
    :return:
    """
    if os.path.exists(path):
        return
    os.makedirs(path, mode=mode)


def file_backup(path, chmod=0o644, backup_dir=None, backup_suffix=None):
    """
    Backup the given file by copying it to a new file
    Copy is preferred to move. Move can keep processes working with the opened file after move operation.

    :param path:
    :param chmod:
    :param backup_dir:
    :param backup_suffix: if defined, suffix is appended to the backup file (e.g., .backup)
    :return:
    """
    backup_path = None
    if os.path.exists(path):
        backup_path = path
        if backup_dir is not None:
            opath, otail = os.path.split(path)
            backup_path = os.path.join(backup_dir, otail)
        if backup_suffix is not None:
            backup_path += backup_suffix

        if chmod is None:
            chmod = os.stat(path).st_mode & 0o777

        with open(path, 'r') as src:
            fhnd, fname = unique_file(backup_path, chmod)
            with fhnd:
                shutil.copyfileobj(src, fhnd)
                backup_path = fname
    return backup_path


def dir_backup(path, chmod=0o644, backup_dir=None):
    """
    Backup the given directory
    :param path:
    :param chmod:
    :param backup_dir:
    :return:
    """
    backup_path = None
    if os.path.exists(path):
        backup_path = path
        if backup_dir is not None:
            opath, otail = os.path.split(path)
            backup_path = os.path.join(backup_dir, otail)

        if chmod is None:
            chmod = os.stat(path).st_mode & 0o777

        backup_path = safe_new_dir(backup_path, mode=chmod)
        os.rmdir(backup_path)
        shutil.copytree(path, backup_path)
    return backup_path


def delete_file_backup(path, chmod=0o644, backup_dir=None, backup_suffix=None):
    """
    Backup the current file by moving it to a new file
    :param path:
    :param chmod:
    :param backup_dir:
    :param backup_suffix: if defined, suffix is appended to the backup file (e.g., .backup)
    :return:
    """
    backup_path = None
    if os.path.exists(path):
        backup_path = file_backup(path, chmod=chmod, backup_dir=backup_dir, backup_suffix=backup_suffix)
        os.remove(path)
    return backup_path


def safe_create_with_backup(path, mode='w', chmod=0o644, backup_dir=None, backup_suffix=None):
    """
    Safely creates a new file, backs up the old one if existed
    :param path:
    :param mode:
    :param chmod:
    :param backup_dir:
    :param backup_suffix: if defined, suffix is appended to the backup file (e.g., .backup)
    :return: file handle, backup path
    """
    backup_path = delete_file_backup(path, chmod, backup_dir=backup_dir, backup_suffix=backup_suffix)
    return safe_open(path, mode, chmod), backup_path


def safe_open_append(path, chmod=None, buffering=None, exclusive=False):
    """Safely open a file for append. If file exists, it is

    :param str path: Path to a file.
    :param int chmod: Same as `mode` for `os.open`, uses Python defaults
        if ``None``.
    :param int buffering: Same as `bufsize` for `os.fdopen`, uses Python
        defaults if ``None``.
    :param bool exclusive: if True, the file cannot exist before
    """
    # pylint: disable=star-args
    open_args = () if chmod is None else (chmod,)
    fdopen_args = () if buffering is None else (buffering,)
    flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
    if exclusive:
        flags |= os.O_EXCL

    return os.fdopen(os.open(path, flags, *open_args), 'a', *fdopen_args)


def safe_new_dir(path, mode=0o755):
    """
    Creates a new unique directory. If the given directory already exists,
    linear incrementation is used to create a new one.


    :param path:
    :param mode:
    :return:
    """
    path, tail = os.path.split(path)
    return _unique_dir(
        path, dirname_pat=(lambda count: "%s_%04d" % (tail, count)),
        count=0, mode=mode)


def _unique_dir(path, dirname_pat, count, mode):
    while True:
        current_path = os.path.join(path, dirname_pat(count))
        try:
            os.makedirs(current_path, mode)
            return os.path.abspath(current_path)

        except OSError as exception:
            # "Dir exists," is okay, try a different name.
            if exception.errno != errno.EEXIST:
                raise
        count += 1


def unique_lineage_name(path, filename, mode=0o777):
    """Safely finds a unique file using lineage convention.

    :param str path: directory path
    :param str filename: proposed filename
    :param int mode: file mode

    :returns: tuple of file object and file name (which may be modified
        from the requested one by appending digits to ensure uniqueness)

    :raises OSError: if writing files fails for an unanticipated reason,
        such as a full disk or a lack of permission to write to
        specified location.

    """
    preferred_path = os.path.join(path, "%s.conf" % (filename))
    try:
        return safe_open(preferred_path, chmod=mode), preferred_path
    except OSError as err:
        if err.errno != errno.EEXIST:
            raise
    return _unique_file(
        path, filename_pat=(lambda count: "%s-%04d.conf" % (filename, count)),
        count=1, mode=mode)


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


def b16encode(x):
    """
    Tries to encode x in hexa-coding
    :param x:
    :return:
    """
    if x is None:
        return None
    if not x:
        return None

    try:
        return base64.b16encode(x)
    except:
        return None


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


def try_get_extension(cert, oid, quiet=True):
    """
    Extracts extension from the certificate
    :param cert:
    :param oid:
    :param quiet:
    :return:
    """
    try:
        return cert.extensions.get_extension_for_oid(oid)

    except ExtensionNotFound:
        return False

    except Exception as e:
        if not quiet:
            logger.error('Exception in getting Extension rest. %s : %s' % (oid, e))
            logger.debug(traceback.format_exc())

    return False


def try_get_subject_key_identifier(cert, compute_if_not_present=True, quiet=True):
    """
    Extracts X509v3 Subject Key Identifier
    :param cert:
    :param compute_if_not_present: if true value is computed if extension is not present
    :param quiet:
    :return:
    """
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER)  # type: SubjectKeyIdentifier
        return ext.value.digest

    except ExtensionNotFound:
        if not compute_if_not_present:
            return False

    except Exception as e:
        if not quiet:
            logger.error('Exception in getting Subject Key Identifier rest. %s' % e)
            logger.debug(traceback.format_exc())

    if compute_if_not_present:
        return try_compute_subject_key_identifier(cert, quiet=quiet)

    return False


def try_compute_subject_key_identifier(cert, quiet=True):
    """
    Tries to compute X509v3 Subject Key Identifier from the certificate public key.
    Useful for certificates without SKID extension present.
    Computed according to RFC 5280 section 4.2.1.2.
    :param cert:
    :param quiet:
    :return:
    """
    try:
        pub_key = cert.public_key()
        ext = SubjectKeyIdentifier.from_public_key(pub_key)
        return ext.digest

    except ExtensionNotFound:
        return False

    except Exception as e:
        if not quiet:
            logger.error('Exception in computing Subject Key Identifier rest. %s' % e)
            logger.debug(traceback.format_exc())

    return False


def try_get_authority_key_identifier(cert, quiet=True):
    """
    Extracts X509v3 Authority Key Identifier
    :param cert:
    :param quiet:
    :return:
    """
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER)  # type: cryptography.x509.AuthorityKeyIdentifier
        return ext.value.key_identifier

    except ExtensionNotFound:
        return False

    except Exception as e:
        if not quiet:
            logger.error('Exception in getting Authority Key Identifier rest. %s' % e)
            logger.debug(traceback.format_exc())

    return False


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
    First tries to extract auth key ID and subject key ID from the cert and compare them.
    If this check fails it falls back to comparing subject & issuer
    :param cert: 
    :param quiet: 
    :return: 
    """
    try:
        subj_key = try_get_subject_key_identifier(cert, quiet=quiet)
        auth_key = try_get_authority_key_identifier(cert, quiet=quiet)
        if subj_key is not False and auth_key is not False and len(subj_key) > 0 and len(auth_key) > 0:
            return subj_key == auth_key

    except Exception as e:
        if not quiet:
            logger.error('Exception in self-signed check. %s' % e)
            logger.debug(traceback.format_exc())

    # Fallback check
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


def try_parse_datetime_string(x):
    """
    Tries to parse try_parse_datetime_string
    :param str: 
    :return: 
    """
    try:
        return dateutil.parser.parse(x)
    except:
        pass
    return None


def try_get_datetime_from_timestamp(x):
    """
    Converts number of seconds to datetime
    :param x:
    :return:
    """
    try:
        return datetime.datetime.fromtimestamp(x)
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


def take(x, cnt=1):
    """
    Takes first cnt elements from x
    :param x:
    :param cnt:
    :return:
    """
    if x is None:
        return None

    return x[0:cnt]


def jsonify(obj):
    """
    Transforms object for transmission
    :param obj:
    :return:
    """
    if obj is None:
        return obj
    elif isinstance(obj, types.ListType):
        return [jsonify(x) for x in obj]
    elif isinstance(obj, types.DictionaryType):
        return {str(k): jsonify(obj[k]) for k in obj}
    elif isinstance(obj, datetime.datetime):
        return unix_time(obj)
    elif isinstance(obj, datetime.timedelta):
        return obj.total_seconds()
    else:
        return obj


def is_string(x):
    """
    Py23 string type detection
    :param x:
    :return:
    """
    return isinstance(x, basestring)


def is_number(x):
    """
    Py23 number detect
    :param x:
    :return:
    """
    return isinstance(x, (int, long, float))


def cli_cmd_sync(cmd, log_obj=None, write_dots=False, on_out=None, on_err=None, cwd=None, shell=True, readlines=True):
    """
    Runs command line task synchronously
    :return: return code, out_acc, err_acc
    """
    from sarge import run, Capture, Feeder
    import time
    import sys

    feeder = Feeder()
    p = run(cmd,
            input=feeder, async=True,
            stdout=Capture(buffer_size=1),
            stderr=Capture(buffer_size=1),
            cwd=cwd,
            shell=shell)

    out_acc = []
    err_acc = []
    ret_code = 1
    log = None
    close_log = False

    # Logging - either filename or logger itself
    if log_obj is not None:
        if isinstance(log_obj, types.StringTypes):
            delete_file_backup(log_obj, chmod=0o600)
            log = safe_open(log_obj, mode='w', chmod=0o600)
            close_log = True
        else:
            log = log_obj

    try:
        while len(p.commands) == 0:
            time.sleep(0.15)

        while p.commands[0].returncode is None:
            out, err = None, None

            if readlines:
                out = p.stdout.readline()
                err = p.stderr.readline()
            else:
                out = p.stdout.read(1)
                err = p.stdout.read(1)

            # If output - react on input challenges
            if out is not None and len(out) > 0:
                out_acc.append(out)

                if log is not None:
                    log.write(out)
                    log.flush()

                if write_dots:
                    sys.stderr.write('.')

                if on_out is not None:
                    on_out(out, feeder, p)

            # Collect error
            if err is not None and len(err) > 0:
                err_acc.append(err)

                if log is not None:
                    log.write(err)
                    log.flush()

                if write_dots:
                    sys.stderr.write('.')

                if on_err is not None:
                    on_err(err, feeder, p)

            p.commands[0].poll()
            time.sleep(0.01)

        ret_code = p.commands[0].returncode

        # Collect output to accumulator
        rest_out = p.stdout.readlines()
        if rest_out is not None and len(rest_out) > 0:
            for out in rest_out:
                out_acc.append(out)
                if log is not None:
                    log.write(out)
                    log.flush()
                if on_out is not None:
                    on_out(out, feeder, p)

        # Collect error to accumulator
        rest_err = p.stderr.readlines()
        if rest_err is not None and len(rest_err) > 0:
            for err in rest_err:
                err_acc.append(err)
                if log is not None:
                    log.write(err)
                    log.flush()
                if on_err is not None:
                    on_err(err, feeder, p)

        return ret_code, out_acc, err_acc

    finally:
        feeder.close()
        if close_log:
            log.close()
