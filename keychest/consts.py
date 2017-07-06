#!/usr/bin/env python
# -*- coding: utf-8 -*-

import cryptography.x509.oid as coid
import util


SIGS = coid.SignatureAlgorithmOID
SIG_ID_MAP = {
    SIGS.RSA_WITH_MD5: 1,

    SIGS.RSA_WITH_SHA1: 12,
    SIGS.RSA_WITH_SHA224: 13,
    SIGS.RSA_WITH_SHA256: 14,
    SIGS.RSA_WITH_SHA384: 15,
    SIGS.RSA_WITH_SHA512: 16,

    SIGS.ECDSA_WITH_SHA1: 22,
    SIGS.ECDSA_WITH_SHA224: 23,
    SIGS.ECDSA_WITH_SHA256: 24,
    SIGS.ECDSA_WITH_SHA384: 25,
    SIGS.ECDSA_WITH_SHA512: 26,

    SIGS.DSA_WITH_SHA1: 32,
    SIGS.DSA_WITH_SHA224: 33,
    SIGS.DSA_WITH_SHA256: 34
}

SID_INV_MAP = util.invert_map(SIG_ID_MAP)


class CertSigAlg(object):
    @staticmethod
    def oid_to_const(oid):
        if oid is None:
            return -1

        oid = util.oid(oid)
        if oid in SIG_ID_MAP:
            return SIG_ID_MAP[oid]
        return -1

    @staticmethod
    def const_to_oid(x):
        if x in SID_INV_MAP:
            return SID_INV_MAP[x]
        return None


class CertKeyType(object):
    RSA = 1
    DSA = 2
    ECC = 3




