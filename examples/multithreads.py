#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from multiprocessing.pool import ThreadPool
from typing import List, Tuple

from binaryai import BinaryAI, Function

DEFAULT_SHA256 = "29b54fcc694f39f108ce0cf6cbf3b8f2b43165b72bfda95e755b52b037a443a7"
DEFAULT_SHA256_1 = "b02c811c053054e2973aec8df4e4027ddf9d5d614bf383cfff62843d635a8d5a"


def run_thread(sha256: str) -> Tuple[str, List[Function]]:
    # Initial BinaryAI client
    bai = BinaryAI()

    result: List[Function] = []
    count = 3
    print(f"list funcs for sha256: {sha256}")
    for func in bai.list_funcs(sha256):
        if count <= 0:
            break
        result.append(func)
        count -= 1
    print("done")
    return (sha256, result)


def main():
    sha256_list = [DEFAULT_SHA256, DEFAULT_SHA256_1]
    params = [(x,) for x in sha256_list]
    with ThreadPool(2) as pool:
        all_results = pool.starmap(run_thread, params)
        for result in all_results:
            print(result[0])
            for func in result[1]:
                print(func.name)


if __name__ == "__main__":
    main()
