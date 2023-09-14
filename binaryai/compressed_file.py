class CompressedFile(object):
    """A compressed file entity.
    Note that a file may have no sha256 which should be empty string,
    e.g. /dev/console and /dev/null.
    """

    def __init__(self, path: str, sha256: str) -> None:
        super().__init__()
        self.path = path
        self.sha256 = sha256
