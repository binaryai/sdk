# BinaryAI Python SDK

![ida](https://img.shields.io/badge/IDA->%3D7.3-brightgreen.svg)
![PUBLISH](https://github.com/binaryai/sdk/workflows/PUBLISH/badge.svg)
[![Gitter](https://badges.gitter.im/binaryai/community.svg)](https://gitter.im/binaryai/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

## Installation

`$ pip install --upgrade binaryai`

For IDA Pro, please download [ida_binaryai.py](https://github.com/binaryai/sdk/releases/latest/download/ida_binaryai.py) and put it to IDA plugins directory.


## Token Registration

A token is all you need to join BinaryAI Community, please [apply it here](https://binaryai.tencent.com/apply-token).


## IDA Pro

### Shortcuts

|   Shortcut   |          Action           |      Scope      |
| :----------: | :-----------------------: | :-------------: |
| Ctrl+Shift+D | Retrieve current function |     Global      |
|      j       |       Next function       | BinaryAI Widget |
|      k       |     Previous function     | BinaryAI Widget |



### Config

To modify the default options, please edit  `binaryai.cfg`, the default path is as follows.

|     OS      |                 Config File                 |
| :---------: | :-----------------------------------------: |
|   Windows   | %APPDATA%/Hex-Rays/IDA Pro/cfg/binaryai.cfg |
| Linux/macOS |     $HOME/.idapro/plugins/binaryai.cfg      |

the supported options are listed below.

```json
{
    "token": "",
    "url": "https://api.binaryai.tencent.com/v1/endpoint",
    "funcset": "",
    "topk": 10,
    "minsize": 3,
    "threshold": 0.9
}
```

### SDK Reference

Please refer to  [BinaryAI SDK Reference](https://binaryai.readthedocs.io/en/latest/binaryai.html#)


## Command Line

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
