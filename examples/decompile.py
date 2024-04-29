#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse

from binaryai import BinaryAI

DEFAULT_SHA256 = "bbe34331e5068d7dc5b990fbef10002358b4ef8e07ab92c0d5620ed60fc36b30"


def main():
    parser = argparse.ArgumentParser(description="decompile binary and do similarity search for a function")
    parser.add_argument("--sha256", required=False, default=DEFAULT_SHA256)
    args = parser.parse_args()

    sha256 = args.sha256

    # Initial BinaryAI client
    bai = BinaryAI()

    # Analyze the file just in case it's not been analyzed.
    bai.wait_until_analysis_done(sha256)

    # Get all functions' offset
    print("list function offset list")
    func_offset_list = bai.list_func_offset(sha256)
    print(func_offset_list)

    # Or you can get a list of functions (in interator) directly
    for func in bai.list_funcs(sha256):
        print("show one function pseudocode")
        print(func.name)
        # print(func.pseudocode)
        break

    # Batch operation
    target_offsets = func_offset_list[:3]
    target_funcs = bai.get_funcs_info(sha256, target_offsets)
    for target_func in target_funcs:
        print(target_func.name)

    # Similar search topk function for given function
    for func_offset in func_offset_list:
        matched_func_list = bai.get_func_match(sha256, func_offset)
        for matched_func in matched_func_list or []:
            print(matched_func.score)
            # print(matched_func.code)
        break

    print("done")


if __name__ == "__main__":
    main()
