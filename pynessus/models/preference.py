__author__ = 'Quentin Kaiser'
__license__ = "Apache 2.0"
__version__ = "0.1"
__contact__ = "kaiserquentin@gmail.com"
__date__ = "2014/16/11"


class PreferenceValue(object):
    """
    """
    def __init__(self):
        self._id = -1
        self._name = None
        self._type = "entry"

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
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        self._type = value


class Preference(object):
    """

    """
    def __init__(self):

        self._name = None
        self._values = []

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def values(self):
        return self._values

    @values.setter
    def values(self, value):
        self._values = value