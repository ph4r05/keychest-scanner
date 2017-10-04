EnigmaBridge Keychest scanner
=============================

`EnigmaBridge <https://enigmabridge.com>`__ Keychest scanner component


Mac OSX installation
--------------------

For new OSX versions (El Capitan and above) the default system python
installation cannot be modified with standard means. There are some
workarounds, but one can also use ``--user`` switch for pip.

::

    pip install --user cryptography


Dependencies
------------

::

    pip install MySql-Python
    pip install SQLAlchemy
    pip install alembic


Ubuntu:

::

    sudo apt-get install python-pip python-dev build-essential libssl-dev libffi-dev libmysqlclient-dev libxml2-dev libxslt1-dev supervisor


CentOS:

::

    sudo yum install -y python python-pip python-devel mysql-devel redhat-rpm-config gcc libxml2 \
    libxml2-devel libxslt libxslt-devel openssl-devel sqlite-devel gcc gcc-c++ make automake autoreconf libtool dialog


PIP update appdirs error
------------------------

Pip may have a problem with updating appdirs due to missing directory. It helps to update this package manually

::

    pip install --upgrade --no-cache appdirs


Database setup
--------------

State is stored in MySQL database.


.. code:: sql

    CREATE DATABASE keychest CHARACTER SET utf8 COLLATE utf8_general_ci;
    GRANT ALL PRIVILEGES ON keychest.* TO 'keychest'@'localhost' IDENTIFIED BY 'keychest_passwd';
    FLUSH PRIVILEGES;


Supervisor
----------

We recommend using supervisor to keep scanner server alive

::

    pip install supervisord

Configuration file for the supervisor :code:`/etc/supervisord.d/keychest.conf`:

::

    [program:keychest]
    directory=/tmp
    command=/usr/bin/epiper keychest-server --debug --server-debug
    user=root
    autostart=true
    autorestart=true
    stderr_logfile=/var/log/keychest-server.err.log
    stdout_logfile=/var/log/keychest-server.out.log


Update configuration

::

    epiper supervisorctl reread
    epiper supervisorctl update


Operation

::

    epiper supervisorctl restart keychest
    epiper supervisorctl status



Troubleshooting
---------------

Symptom: :code:`ImportError: No module named ssl_tls`

Solution:

::

    /bin/rm -rf /usr/local/lib/python2.7/dist-packages/scapy*
    pip install scapy==2.3.2
    ./install.sh

