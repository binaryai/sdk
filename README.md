# BinaryAI Python SDK

![PUBLISH](https://github.com/binaryai/sdk/workflows/PUBLISH/badge.svg)
[![readthedocs](https://readthedocs.org/projects/binaryai/badge/?version=stable&style=flat)](https://binaryai.readthedocs.io/)
[![Downloads](https://pepy.tech/badge/binaryai/month)](https://pepy.tech/project/binaryai/month)
[![Gitter](https://badges.gitter.im/binaryai/community.svg)](https://gitter.im/binaryai/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

[BinaryAI](https://www.binaryai.cn) is a binary file security analysis platform. This SDK aims at providing
a simple client to upload file and get analysis result. It also works as
a demo on calling BinaryAI's GraphQL API directly.

To use SDK, you need a valid credential. Read [BinaryAI docs](https://www.binaryai.cn/doc/) about detailed instructions.

## Dependency

Python >= 3.9

## Download and install

```bash
python3 -m pip install binaryai
```

## Quick start

See the [SDK document](https://binaryai.readthedocs.io) for guide.

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

## Additional Reading

Read the [Changelog](https://www.binaryai.cn/doc/zh/releasenotes/releasenotes.html) of our product, and hope you can also have fun reading papers related to our job:

1. Yu, Zeping, et al. "Codecmr: Cross-modal retrieval for function-level binary source code matching." Advances in Neural Information Processing Systems 33 (2020): 3872-3883.
2. Yu, Zeping, et al. "Order matters: Semantic-aware neural networks for binary code similarity detection." Proceedings of the AAAI conference on artificial intelligence. Vol. 34. No. 01. 2020.
3. Li, Zongjie, et al. "Unleashing the power of compiler intermediate representation to enhance neural program embeddings." Proceedings of the 44th International Conference on Software Engineering. 2022.
4. Wong, Wai Kin, et al. "Deceiving Deep Neural Networks-Based Binary Code Matching with Adversarial Programs." 2022 IEEE International Conference on Software Maintenance and Evolution (ICSME). IEEE, 2022.
5. Wang, Huaijin, et al. "Enhancing DNN-Based Binary Code Function Search With Low-Cost Equivalence Checking." IEEE Transactions on Software Engineering 49.1 (2022): 226-250.
6. Jia, Ang, et al. "1-to-1 or 1-to-n? Investigating the Effect of Function Inlining on Binary Similarity Analysis." ACM Transactions on Software Engineering and Methodology 32.4 (2023): 1-26.
7. Wang, Huaijin, et al. "sem2vec: Semantics-aware Assembly Tracelet Embedding." ACM Transactions on Software Engineering and Methodology 32.4 (2023): 1-34.
8. Jiang, Ling, et al. "Third-Party Library Dependency for Large-Scale SCA in the C/C++ Ecosystem: How Far Are We?." Proceedings of the 32nd ACM SIGSOFT International Symposium on Software Testing and Analysis. 2023.
