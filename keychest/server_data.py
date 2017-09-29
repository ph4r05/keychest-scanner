#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Server data classes
"""

from past.builtins import cmp
import collections


class EmailArtifactTypes(object):
    PGP_KEY = 1
    PGP_FILE = 2
    PGP_SIG = 4
    PKCS7_SIG = 8
    PKCS7_FILE = 16

    def __init__(self):
        pass


class EmailArtifact(object):
    """
    Email artifact object
    """
    def __init__(self, *args, **kwargs):
        self.payload = kwargs.get('payload')
        self.filename = kwargs.get('filename')
        self.ftype = kwargs.get('ftype')

    def __repr__(self):
        return '<EmailArtifact(ftype=%r, filename=%r, payload=%r)>' % (self.ftype, self.filename, self.payload)

