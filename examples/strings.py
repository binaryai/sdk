#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse

from binaryai import BinaryAI

DEFAULT_SHA256 = "29b54fcc694f39f108ce0cf6cbf3b8f2b43165b72bfda95e755b52b037a443a7"


def main():
    parser = argparse.ArgumentParser(description="get a list of strings found in a given file")
    parser.add_argument("--sha256", required=False, default=DEFAULT_SHA256)
    args = parser.parse_args()

    sha256 = args.sha256

    # Initial BinaryAI client
    bai = BinaryAI()

    # Analyze the file just in case it's not been analyzed.
    bai.wait_until_analysis_done(sha256)

    # Get all ASCII strings
    ascii_strings = bai.get_all_ascii_strings(sha256)
    for s in ascii_strings:
        print(s)

    print("done")


if __name__ == "__main__":
    main()
