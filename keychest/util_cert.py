#!/usr/bin/env python
# -*- coding: utf-8 -*-

import cryptography.x509.oid as coid
import util
import consts
import re
import logging
import traceback

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.x509.oid import ExtensionOID
from cryptography.x509 import ExtensionNotFound, PolicyInformation

from keychest.tls_domain_tools import TlsDomainTools

logger = logging.getLogger(__name__)


# Extended validation policy OIDs
#   Per CA defined
#   https://stackoverflow.com/questions/14705157/how-to-check-if-a-x509-certificate-has-extended-validation-switched-on
EV_OIDS = [
    ObjectIdentifier("1.3.6.1.4.1.34697.2.1"),
    ObjectIdentifier("1.3.6.1.4.1.34697.2.2"),
    ObjectIdentifier("1.3.6.1.4.1.34697.2.1"),
    ObjectIdentifier("1.3.6.1.4.1.34697.2.3"),
    ObjectIdentifier("1.3.6.1.4.1.34697.2.4"),
    ObjectIdentifier("1.2.40.0.17.1.22"),
    ObjectIdentifier("2.16.578.1.26.1.3.3"),
    ObjectIdentifier("1.3.6.1.4.1.17326.10.14.2.1.2"),
    ObjectIdentifier("1.3.6.1.4.1.17326.10.8.12.1.2"),
    ObjectIdentifier("1.3.6.1.4.1.6449.1.2.1.5.1"),
    ObjectIdentifier("2.16.840.1.114412.2.1"),
    ObjectIdentifier("2.16.528.1.1001.1.1.1.12.6.1.1.1"),
    ObjectIdentifier("2.16.840.1.114028.10.1.2"),
    ObjectIdentifier("1.3.6.1.4.1.14370.1.6"),
    ObjectIdentifier("1.3.6.1.4.1.4146.1.1"),
    ObjectIdentifier("2.16.840.1.114413.1.7.23.3"),
    ObjectIdentifier("1.3.6.1.4.1.14777.6.1.1"),
    ObjectIdentifier("1.3.6.1.4.1.14777.6.1.2"),
    ObjectIdentifier("1.3.6.1.4.1.22234.2.5.2.3.1"),
    ObjectIdentifier("1.3.6.1.4.1.782.1.2.1.8.1"),
    ObjectIdentifier("1.3.6.1.4.1.8024.0.2.100.1.2"),
    ObjectIdentifier("1.2.392.200091.100.721.1"),
    ObjectIdentifier("2.16.840.1.114414.1.7.23.3"),
    ObjectIdentifier("1.3.6.1.4.1.23223.2"),
    ObjectIdentifier("1.3.6.1.4.1.23223.1.1.1"),
    ObjectIdentifier("1.3.6.1.5.5.7.1.1"),
    ObjectIdentifier("2.16.756.1.89.1.2.1.1"),
    ObjectIdentifier("2.16.840.1.113733.1.7.48.1"),
    ObjectIdentifier("2.16.840.1.114404.1.1.2.4.1"),
    ObjectIdentifier("2.16.840.1.113733.1.7.23.6"),
    ObjectIdentifier("1.3.6.1.4.1.6334.1.100.1"),
]


def try_get_key_type(pub):
    """
    Determines pubkey type
    :param pub:
    :return:
    """
    if isinstance(pub, RSAPublicKey):
        return consts.CertKeyType.RSA
    elif isinstance(pub, DSAPublicKey):
        return consts.CertKeyType.DSA
    elif isinstance(pub, EllipticCurvePublicKey):
        return consts.CertKeyType.ECC
    else:
        return -1


def try_get_pubkey_size(pub):
    """
    Determines public key bit size
    :param pub:
    :return:
    """
    if isinstance(pub, RSAPublicKey):
        return pub.key_size
    elif isinstance(pub, DSAPublicKey):
        return pub.key_size
    elif isinstance(pub, EllipticCurvePublicKey):
        return pub.key_size
    else:
        return -1


def cloudflare_altnames(altnames):
    """
    Returns cloudflares alt names
    :param altnames:
    :return:
    """
    return [x for x in altnames if
            x is not None and (
                x.endswith('.cloudflaressl.com') or
                re.match(r'^ssl[0-9]+.cloudflare.com$', x))]


def try_cert_is_ev(cert, quiet=True):
    """
    Determines if the certificate has extended validation
    :param cert:
    :param quiet:
    :return:
    """
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES)
        if ext is None:
            return False

        for policy in ext.value:
            if not isinstance(policy, PolicyInformation):
                continue
            if policy.policy_identifier in EV_OIDS:
                return True

    except ExtensionNotFound:
        return False

    except Exception as e:
        if not quiet:
            logger.error('Exception in getting EV status. %s' % e)
            logger.debug(traceback.format_exc())

    return False


def try_cert_is_cn_wildcard(cert, quiet=True):
    """
    Returns true if the certificate has *. in the CN
    :param cert:
    :param quiet:
    :return:
    """
    try:
        cname = util.try_get_cname(cert)
        return TlsDomainTools.has_wildcard(cname)

    except Exception as e:
        if not quiet:
            logger.error('Exception in getting CN wildcard status. %s' % e)
            logger.debug(traceback.format_exc())

    return False


def try_cert_alt_wildcard_num(cert):
    """
    Returns number of wildcard domain in the alt domains
    :param cert:
    :return:
    """
    alt_names = [util.utf8ize(x) for x in util.try_get_san(cert)]
    num_wilds = sum([1 for x in alt_names if TlsDomainTools.has_wildcard(x)])
    return num_wilds

