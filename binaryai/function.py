from typing import List, Optional


class Function(object):
    """A function entity that represents a decompiled function."""

    def __init__(self, name: str, offset: int, pseudocode: str, embedding: Optional[List[float]] = None):
        self.name = name
        self.offset = offset
        self.pseudocode = pseudocode
        self.embedding = embedding


class MatchedFunction(object):
    """Matched function entity by using similarity search.
    Differ from Function class, this class is a matched function result
    with only score, code and other fields, but no bytes and fileoffset
    which represents an function in a executable binary.
    So this is rather not an actual decompiled function.

    Note that this class is experiment and maybe changed in the future.
    """

    def __init__(self, score: float, code: str) -> None:
        super().__init__()
        self.score = score
        self.code = code
