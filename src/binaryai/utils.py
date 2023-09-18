#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from hashlib import sha256


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
