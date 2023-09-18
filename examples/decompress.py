#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse

from binaryai import BinaryAI

DEFAULT_SHA256 = "472aa646840dda3036dd1a2ec2c3f8383fbda1b3c588b079b757fa0522cc16c3"


def main():
    parser = argparse.ArgumentParser(description="get a list of files from compressed file")
    parser.add_argument("--sha256", required=False, default=DEFAULT_SHA256)
    args = parser.parse_args()

    sha256 = args.sha256

    # Initial BinaryAI client
    bai = BinaryAI()

    # Analyze the file just in case it's not been analyzed.
    bai.wait_until_analysis_done(sha256)

    # Get all compreessed files
    compressed_files = bai.get_compressed_files(sha256)
    for compressed_file in compressed_files:
        print(compressed_file.__dict__)

    print("done")


if __name__ == "__main__":
    main()
