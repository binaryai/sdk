#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from hashlib import sha256
from typing import Any, Dict, List

from binaryai.exceptions import BinaryAIResponseError


def sha256sum(path: str) -> str:
    """
    Computes sha256 hash sum of a file.

    Args:
        path: path of file

    Returns:
        hex digest of sha256
    """
    hash = sha256()
    with open(path, "rb") as f:
        for buf in iter(lambda: f.read(4096), b""):
            hash.update(buf)
    return str(hash.hexdigest())


def get_result(_input: Dict, keys: List) -> Any:
    """
    Returns:
        dict value specified by keys
    Raises:
        BinaryAIResponseError: if can not return correctly
    """
    if not keys:
        return _input

    pre, p = None, _input
    for k in keys:
        try:
            pre, p = p, p[k]
        except TypeError:
            raise BinaryAIResponseError(f"field value {pre} is not a dict")
        except BaseException:
            raise BinaryAIResponseError(f"{k} field missing in response")

    return p
