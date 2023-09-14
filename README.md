# BinaryAI Python SDK

![PUBLISH](https://github.com/binaryai/sdk/workflows/PUBLISH/badge.svg)
[![Downloads](https://pepy.tech/badge/binaryai/month)](https://pepy.tech/project/binaryai/month)
[![Gitter](https://badges.gitter.im/binaryai/community.svg)](https://gitter.im/binaryai/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

BinaryAI is a binary file security analysis platform. This SDK aims at providing
a simple client to upload file and get analysis result. It can also works as
a demo on calling BinaryAI's GraphQL API directly.
The Python3 SDK for BinaryAI provides an abstracted client module to simplify the procedure of uploading file for analysis.

To use SDK, you need a valid credentials. Read [BinaryAI docs](https://www.binaryai.cn/doc/) about detailed instructions.

## Dependency

Python >= 3.8

## Download and installation

```bash
python3 -m pip install binaryai
```

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## Internals

### Endpoints

The default endpoint is `https://api.binaryai.cn/v1/endpoint`.

### API Credentials

API Credentials are used for signing requests. We suggest you using our SDK or our library to sign it, but you can also
have your own implementation. We are using the signing method `TC3-HMAC-SHA256`, same with the Tencent Cloud. You can
read their [document](https://cloud.tencent.com/document/product/213/30654) about how to sign requests. BinaryAI would
require following fields:

```toml
Region  = "ap-shanghai"
service = "binaryai"
Action  = "BinaryAI"
Version = "2023-04-15"
```
