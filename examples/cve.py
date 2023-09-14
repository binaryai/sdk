#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse

from binaryai import BinaryAI, BinaryAIException

DEFAULT_SHA256 = "29b54fcc694f39f108ce0cf6cbf3b8f2b43165b72bfda95e755b52b037a443a7"


def main():
    parser = argparse.ArgumentParser(description="get a list of CVEs found against a given file")
    parser.add_argument("--sha256", required=False, default=DEFAULT_SHA256)
    args = parser.parse_args()

    sha256 = args.sha256

    # Initial BinaryAI client
    bai = BinaryAI()

    try:
        # Analyze the file just in case it's not been analyzed.
        bai.wait_until_analysis_done(sha256)

        # Get all CVE names in string type
        cve_names = bai.get_all_cve_names(sha256)
        for cve_name in cve_names:
            print(cve_name)

        # Or you can get all CVE in object type
        cve_list = bai.get_all_cves(sha256)
        for cve in cve_list:
            print(cve.name)

        print("done")
    except BinaryAIException as e:
        print(f"analysis error: {e}")


if __name__ == "__main__":
    main()
