#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse

from binaryai import BinaryAI, BinaryAIException


def main():
    parser = argparse.ArgumentParser(description="upload a file and analyze it")
    parser.add_argument("--file", "-f", required=True)
    args = parser.parse_args()

    # Initial BinaryAI client
    bai = BinaryAI()

    try:
        # Upload a filepath
        # If file exists on server, it will not actually
        # upload the file; otherwise, it will upload the
        # file to the server.
        sha256 = bai.upload(args.file)
        print(f"uploaded file: {sha256}")

        # Analyze a file identified by a sha256
        # If it's the first time to analyze, this may takes
        # some time, otherwise it should be a very quick call.
        # Wait for unlimited time
        bai.wait_until_analysis_done(sha256, timeout=-1)

        # Retreive analyze results of this file
        # .....

        print("done")
    except BinaryAIException as e:
        print(f"upload or analyze file error: {e}")


if __name__ == "__main__":
    main()
