#!/usr/bin/env python
# -*- coding: utf-8 -*-


def failjob(job):
    """
    Fails job
    :param job: 
    :return: 
    """
    job.mark_as_failed()

    if job.deleted:
        return

    job.delete()
    job.failed()

