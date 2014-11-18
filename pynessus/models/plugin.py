__author__ = 'Quentin Kaiser'
__license__ = "Apache 2.0"
__version__ = "0.1"
__contact__ = "kaiserquentin@gmail.com"
__date__ = "2014/16/11"


class PluginFamily(object):

    def __init__(self):
        self._id = -1
        self._name = None
        self._plugin_count = 0
        self._status = "enabled"
        self._plugins = []

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        self._id = value

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def plugin_count(self):
        return self._plugin_count

    @plugin_count.setter
    def plugin_count(self, value):
        self._plugin_count = value

    @property
    def status(self):
        return self._status

    @status.setter
    def status(self, value):
        self._status = value

    @property
    def plugins(self):
        return self._plugins

    @plugins.setter
    def plugins(self, value):
        self._plugins = value


class Plugin(object):

    def __init__(self):
        self._id = -1
        self._name = None
        self._filename = None
        self._status = "enabled"

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        self._id = int(value)

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def filename(self):
        return self._filename

    @filename.setter
    def filename(self, value):
        self._filename = value

    @property
    def status(self):
        return self._status

    @status.setter
    def status(self, value):
        self._status = value
