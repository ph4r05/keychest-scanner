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

