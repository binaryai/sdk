class FileNotExistError(Exception):
    """
    FileNotExistError means the sha256 just uploaded is not found.
    Normally this error does not occur. If it does, it means that there is
    a problem with the server
    """

    pass


class FileRequiredError(Exception):
    """
    FileRequiredError means BinaryAI requires the file, but you are not providing it.
    This error might occur if you are only providing hash to the BinaryAI. Consider provide the original file as well.
    """

    pass
