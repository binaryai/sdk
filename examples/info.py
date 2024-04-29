#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse

from binaryai import BinaryAI

DEFAULT_SHA256 = "bbe34331e5068d7dc5b990fbef10002358b4ef8e07ab92c0d5620ed60fc36b30"


def main():
    parser = argparse.ArgumentParser(description="fetch file infos and analysis overview")
    parser.add_argument("--sha256", required=False, default=DEFAULT_SHA256)
    args = parser.parse_args()

    sha256 = args.sha256

    # Initial BinaryAI client
    bai = BinaryAI()

    # Analyze the file just in case it's not been analyzed.
    bai.wait_until_analysis_done(sha256)

    # Get all uploaded filenames
    print("get all uploaded filenames")
    filenames = bai.get_filenames(sha256)
    print(filenames)

    # Get MIME type
    print("get MIME type")
    mime_type = bai.get_mime_type(sha256)
    print(mime_type)

    # Get size in bytes
    print("get size in bytes")
    size = bai.get_size(sha256)
    print(size)

    # Get analysis overview
    print("get analysis overview")
    overview = bai.get_overview(sha256)
    print(overview)

    print("done")


if __name__ == "__main__":
    main()
