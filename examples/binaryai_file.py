#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from binaryai import BinaryAI, BinaryAIFile

# sha256 and md5 of the same file
DEFAULT_SHA256 = "bbe34331e5068d7dc5b990fbef10002358b4ef8e07ab92c0d5620ed60fc36b30"
DEFAULT_MD5 = "c46b449d5460d45ecec2bb88a1975b3b"


def main():
    # Initial BinaryAIFile
    # param sha256 and md5 can not empty at the same time
    bf1 = BinaryAIFile(BinaryAI(), sha256=DEFAULT_SHA256)
    bf2 = BinaryAIFile(BinaryAI(), md5=DEFAULT_MD5)

    # bf1 and bf2 represent the same file
    bf1_files = bf1.get_filenames()
    bf2_files = bf2.get_filenames()
    assert bf1_files == bf2_files

    print(bf1_files)
    print(bf2_files)
    print(bf1.get_khash_info())

    print("done")


if __name__ == "__main__":
    main()
