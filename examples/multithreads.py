#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from multiprocessing.pool import ThreadPool
from typing import List, Tuple

from binaryai import BinaryAI, Function

DEFAULT_SHA256 = "bbe34331e5068d7dc5b990fbef10002358b4ef8e07ab92c0d5620ed60fc36b30"
DEFAULT_SHA256_1 = "289616b59a145e2033baddb8a8a9b5a8fb01bdbba1b8cf9acadcdd92e6cc0562"


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
