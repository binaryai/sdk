# BinaryAI Python SDK

![ida](https://img.shields.io/badge/IDA->%3D7.3-brightgreen.svg)
![PUBLISH](https://github.com/binaryai/sdk/workflows/PUBLISH/badge.svg)
[![Gitter](https://badges.gitter.im/binaryai/community.svg)](https://gitter.im/binaryai/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

## Introduction

BinaryAI is a Neural Search Engine for binaries developed by Tencent Security KEEN Lab, aiming to help security researchers match the binary functions with the most possible source codes.

BinaryAI provides three ways to access core APIs of BinaryAI Search Engine framework.

1. Python SDK

   BinaryAI provides users with the ability to write custom tools to analyze binaries. Please refer to [BinaryAI SDK Reference](https://binaryai.readthedocs.io/en/latest/binaryai.html#)

2. IDA plugin

   BinaryAI provides an IDA plugin to assist reverse engineering analysis with the IDA Pro user interface. The IDA Pro plugin enables users to apply BinaryAI retrieval results from source codes of millions of functions in the cloud to the file loaded in IDA Pro with a few clicks.

3. Command line tool

   The command line tool now facilitates users with easy access to manage their own private function sets,  but will be broadened to support more features in the future. 

Please see the [Documentation]( https://binaryai.readthedocs.io/ ) for more details.

## Installation

```shell
pip install --upgrade binaryai
# then you can add the binaryai plugin into $IDAUSR
binaryai install_ida_plugin
```

## Token Registration

A token is all you need to join BinaryAI Community, please [apply for it here](https://binaryai.tencent.com/apply-token).
