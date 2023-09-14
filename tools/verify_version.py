#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""This script is used to check whether the version number
meets the requirements from `https://semver.org`.

Typical usage example:

python3 verify_version.py 1.1.0
"""

import re
import sys


def main():
    version = sys.argv[1]
    # https://regex101.com/r/Ly7O1x/3/
    regex = re.compile(
        r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"  # noqa: E501
    )

    # full text matching
    if regex.fullmatch(version) is None:
        print("invalid tag: {}".format(version))
        exit(1)
    exit(0)


if __name__ == "__main__":
    main()
