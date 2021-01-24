#!/usr/bin/env python
# coding: utf-8
from setuptools import setup, find_packages

setup(
    name='binaryai',
    author='binaryai',
    author_email='binaryai@tencent.com',
    packages=find_packages(),
    setup_requires=['setuptools_scm'],
    use_scm_version=True,
    install_requires=['requests', 'Click'],
    url="https://github.com/binaryai/sdk",
    license='GPLv3',
    classifiers=[
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Operating System :: OS Independent",
    ],
    project_urls={
        "Documentation": "https://binaryai.readthedocs.io/",
        "Source": "https://github.com/binaryai/sdk",
    },
    python_requires=">=2.7",
    entry_points='''
        [console_scripts]
        binaryai=binaryai.cli:main
    '''
)
