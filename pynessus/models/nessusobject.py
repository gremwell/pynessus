class NessusObject(object):

    def __init__(self, server):
        self._id = None
        self._server = server

    def save(self):
        if self._id is None:
            return getattr(self._server, "create_%s" % self.__class__.__name__.lower())(self)
        else:
            return getattr(self._server,"update_%s" % self.__class__.__name__.lower())(self)

    def delete(self):
        if self._id is not None:
            return getattr(self._server, "delete_%s" % self.__class__.__name__.lower())(self)

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, _id):
        self._id = _id