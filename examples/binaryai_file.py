#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from binaryai import BinaryAI, BinaryAIFile

# sha256 and md5 of the same file
DEFAULT_SHA256 = "29b54fcc694f39f108ce0cf6cbf3b8f2b43165b72bfda95e755b52b037a443a7"
DEFAULT_MD5 = "dc62248e4b521c1884a0c4a4261c52b8"


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

    print(bf1.get_all_cve_names())
    print(bf2.get_all_licenses())

    print("done")


if __name__ == "__main__":
    main()
