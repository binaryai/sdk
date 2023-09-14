#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from binaryai import BinaryAI, BinaryAIException

# sha256 and md5 of the same file
DEFAULT_MD5 = "dc62248e4b521c1884a0c4a4261c52b8"


def main():
    bai = BinaryAI()

    try:
        sha256 = bai.get_sha256(DEFAULT_MD5)
        print(sha256)
        print("done")
    except BinaryAIException as e:
        print(f"analysis error: {e}")


if __name__ == "__main__":
    main()
