__author__ = 'dusanklinec'


class MicroMock(object):
    """
    Micro mock
    """
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

