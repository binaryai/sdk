class BinaryAIException(Exception):
    def __init__(self, code, msg, data=None, raw=None):
        super(BinaryAIException, self).__init__(code, msg, data, raw)
        self._code = code
        self._msg = msg
        self._data = data
        self._raw = raw

    @property
    def code(self):
        return self._code

    @property
    def data(self):
        return self._data

    def __str__(self):
        return "{}: {}".format(self._code, self._msg)
