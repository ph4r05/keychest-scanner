#!/usr/bin/env python
# -*- coding: utf-8 -*-

import phpserialize
import collections
import json
import util


def failjob(job, e=None):
    """
    Fails job
    :param job: 
    :return: 
    """
    job.mark_as_failed()

    if job.deleted:
        return

    job.delete()
    job.failed(e)


class MainEventWrapper(object):
    """
    Base event object to submit to the redis queue.
    
    {
        "displayName": "App\\Listeners\\ScanJobListener", 
        "attempts": 0, 
        "id": "ALWzGVFyJDFD5z6CTRUTBaILTfJ5MfqK", 
        "job": "Illuminate\\Queue\\CallQueuedHandler@call", 
        "timeout": null, 
        "data": {
            "command": "O:36:\"Illuminate\\Events\\CallQueuedListener\":6:
            {
                s:5:\"class\";s:29:\"App\\Listeners\\ScanJobListener\";s:6:\"method\";s:6:\"handle\";s:4:\"data\";a:1:
                {
                    i:0;O:26:\"App\\Events\\ScanJobProgress\":2:
                    {
                        s:7:\"\u0000*\u0000test\";i:1;s:6:\"socket\";N;
                    }
                }s:5:\"tries\";N;s:7:\"timeout\";N;s:6:\"\u0000*\u0000job\";N;
            }", 
            "commandName": "Illuminate\\Events\\CallQueuedListener"
        }, 
        "maxTries": null
    }
    """
    def __init__(self, display_name=None, attempts=0, id=None, job=None, timeout=None, command=None,
                 command_name=None, max_tries=0):
        self.display_name = display_name
        self.attempts = attempts
        self.id = id
        self.job = job
        self.timeout = timeout
        self.command = command
        self.command_name = command_name
        self.max_tries = max_tries

    def set_event(self, evt):
        """
        Sets event object
        :param evt: 
        :return: 
        """
        self.command.set_event(evt)

    def get_event(self):
        """
        Returns underlying event or none
        :return: 
        """
        return self.command.get_event()

    def encode(self):
        """
        Encode to the form for sending to the queue
        :return: 
        """
        js = collections.OrderedDict()
        js['displayName'] = self.display_name
        js['attempts'] = self.attempts
        js['id'] = self.id
        js['job'] = self.job
        js['timeout'] = self.timeout
        js['data'] = collections.OrderedDict()

        js['data']['command'] = None
        if self.command is not None:
            js['data']['command'] = phpserialize.dumps(self.command, object_hook=util.php_obj_hook)

        js['data']['commandName'] = self.command_name
        js['maxTries'] = self.max_tries
        return js


class CallQueuedListener(object):
    """
    Command for the main event wrapper.
    """
    def __init__(self, cls='App\\Listeners\\ScanJobListener', method='handle', data=None, tries=None, timeout=None,
                 invoker='App\\Keychest\\Events\\Ph4CallQueuedListener'):
        self.invoker = invoker
        self.cls = cls
        self.method = method
        self.data = data if data is not None else []
        self.tries = tries
        self.timeout = timeout

    def set_event(self, evt):
        """
        Sets actual event to the hierarchy
        :param evt: 
        :return: 
        """
        self.data = [evt]

    def get_event(self):
        """
        Returns event if any
        :return: 
        """
        if self.data is None or len(self.data) == 0:
            return None
        return self.data[0]

    def to_php(self):
        """
        php serialization
        :return: 
        """
        js = collections.OrderedDict()
        js['class'] = self.cls
        js['method'] = self.method
        js['data'] = [util.phpize(x) for x in self.data]
        js['tries'] = self.tries
        js['timeout'] = self.timeout

        obj = phpserialize.phpobject('App\\Keychest\\Events\\Ph4CallQueuedListener', js)
        util.php_set_protected(obj, 'job', None)

        return obj


class EvtBase(object):
    """
    Base event object
    """
    def to_php(self):
        """
        PHP representation
        :return: 
        """
        return None


class EvtScanJobProgress(EvtBase):
    """
    ScanJobProgress event
    """
    def __init__(self, json_data=None):
        self.json_data = json_data

    def to_php(self):
        """
        PHP representation
        :return: 
        """
        js = collections.OrderedDict()
        js['socket'] = None
        obj = phpserialize.phpobject('App\\Events\\ScanJobProgress', js)
        util.php_set_protected(obj, 'json_data', json.dumps(self.json_data))

        return obj


def default_envelope():
    """
    Returns default event envelope
    :return: 
    """
    evt = MainEventWrapper(display_name='App\\Listeners\\ScanJobListener',
                           id=util.random_alphanum(32),
                           job='Illuminate\\Queue\\CallQueuedHandler@call',
                           command_name='App\\Keychest\\Events\\Ph4CallQueuedListener')
    evt.command = CallQueuedListener()
    return evt


def scan_job_progress(data=None):
    """
    Returns event wrapped in the master event envelope
    :param data: 
    :return: 
    """
    envelope = default_envelope()
    evt = EvtScanJobProgress(data)
    envelope.set_event(evt)

    return envelope

