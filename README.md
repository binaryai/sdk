# BinaryAI Python SDK

![ida](https://img.shields.io/badge/IDA->%3D7.3-brightgreen.svg)

## Installation

`$ pip install binaryai`

## Usage

### command line

```shell
$ binaryai --help

 ____  _                           _    ___
| __ )(_)_ __   __ _ _ __ _   _   / \  |_ _|
|  _ \| | '_ \ / _` | '__| | | | / _ \  | |
| |_) | | | | | (_| | |  | |_| |/ ___ \ | |
|____/|_|_| |_|\__,_|_|   \__, /_/   \_\___|
                          |___/

Usage: binaryai [OPTIONS] COMMAND [ARGS]...

Options:
  -u, --url TEXT    api url  [default: https://api.binaryai.tencent.com/v1/endpoint]
  -t, --token TEXT  user token
  -h, --help        Show this message and exit.
  -v, --version     Show version

Commands:
  create_funcset  create a new function set and add functions if needed
  query_funcset   get function set info by id
  query_function  get function info by given id
  search_funcs    search top similar functions of the query
```
