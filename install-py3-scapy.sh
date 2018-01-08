#!/bin/sh
# Installs scapy for python 3
set -e

cd /tmp
/bin/rm -rf /tmp/scapy-ssl_tls

git clone https://github.com/tintinweb/scapy-ssl_tls.git scapy-ssl_tls
cd scapy-ssl_tls

git checkout remotes/origin/py3compat
python3 setup.py build
python3 setup.py install
