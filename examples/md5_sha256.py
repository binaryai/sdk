#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from binaryai import BinaryAI

# sha256 and md5 of the same file
DEFAULT_MD5 = "c46b449d5460d45ecec2bb88a1975b3b"


def main():
    bai = BinaryAI()

    sha256 = bai.get_sha256(DEFAULT_MD5)
    print(sha256)
    print("done")


if __name__ == "__main__":
    main()
