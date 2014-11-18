__author__ = 'Quentin Kaiser'
__license__ = "Apache 2.0"
__version__ = "0.1"
__contact__ = "kaiserquentin@gmail.com"
__date__ = "2014/16/11"


class Report(object):
    """
    A Nessus Report instance.

    Attributes:

    _Google Python Style Guide:
    http://google-styleguide.googlecode.com/svn/trunk/pyguide.html
    """

    def __init__(self, name=None, readable_name=None, status=None, timestamp=0, content=None, _format="nessus.v2"):
        """Constructor"""
        self._name = name
        self._readable_name = readable_name
        self._status = status
        self._timestamp = timestamp
        self._content = content
        self._format = _format

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name):
        self._name = name

    @property
    def readable_name(self):
        return self._readable_name

    @readable_name.setter
    def readable_name(self, readable_name):
        self._readable_name = readable_name

    @property
    def status(self):
        return self._status

    @status.setter
    def status(self, status):
        self._status = status

    @property
    def timestamp(self):
        return self._timestamp

    @timestamp.setter
    def timestamp(self, timestamp):
        self._timestamp = timestamp

    @property
    def content(self):
        return self._content

    @content.setter
    def content(self, content):
        self._content = content

    @property
    def format(self):
        return self._format

    @format.setter
    def format(self, _format):
        self._format = _format

    def save(self, filename=None):
        """
        Save the report content to a file.
        Params:
            filename(string): filename
        Returns:
            True if successful, False otherwise.
        """
        if filename is None:
            filename = "%s.%s" % (self._name, self._format)
        with open(filename, "wb") as f:
            f.write(self.content)
        return filename
