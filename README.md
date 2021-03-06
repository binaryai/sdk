# BinaryAI Python SDK

![ida](https://img.shields.io/badge/IDA->%3D7.3-brightgreen.svg)
![PUBLISH](https://github.com/binaryai/sdk/workflows/PUBLISH/badge.svg)
[![Downloads](https://pepy.tech/badge/binaryai/month)](https://pepy.tech/project/binaryai/month)
[![Gitter](https://badges.gitter.im/binaryai/community.svg)](https://gitter.im/binaryai/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

## Introduction

BinaryAI is a Neural Search Engine for binaries developed by Tencent Security KEEN Lab, aiming to help security researchers match the most similar source codes in a given binary.

BinaryAI provides three ways to access core APIs of BinaryAI Search Engine framework.

1. Python SDK

   BinaryAI provides users with the ability to write custom tools to analyze binaries. Please refer to [BinaryAI SDK Reference](https://binaryai.readthedocs.io/en/latest/binaryai.html#).

2. IDA plugin

   BinaryAI provides an IDA plugin to assist reverse engineering analysis with the IDA Pro user interface. The IDA Pro plugin enables users to apply BinaryAI retrieval results from source codes of millions of functions in the cloud to the file loaded in IDA Pro with a few clicks.

3. Command line tool

   The command line tool now facilitates users with easy access to install the IDA plugin. 


## Installation

```shell
pip install --upgrade binaryai
# then you can add the binaryai plugin into $IDAUSR
binaryai install_ida_plugin
```

## Token Registration

A token is all you need to join BinaryAI Community, please [apply for it here](https://binaryai.tencent.com/apply-token).

## Documentation

Please see the [Documentation](https://binaryai.readthedocs.io/en/latest/index.html) for more details.

### Additional Reading

[Order Matters: Semantic-Aware Neural Networksfor Binary Code Similarity Detection](https://keenlab.tencent.com/en/whitepapers/Ordermatters.pdf)

[CodeCMR: Cross-Modal Retrieval For Function-Level Binary Source Code Matching](https://keenlab.tencent.com/zh/whitepapers/neurips-2020-cameraready.pdf)

