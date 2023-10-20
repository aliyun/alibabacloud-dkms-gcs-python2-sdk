# coding=utf-8

import os
from setuptools import setup, find_packages

"""
setup module for alibabacloud-dkms-gcs-python2.

Created on 04/23/2022

@author: Alibaba Cloud SDK
"""

packages = find_packages()
NAME = "alibabacloud-dkms-gcs-python2"
DESCRIPTION = "AlibabaCloud DKMS-GCS SDK for Python2"
AUTHOR = "Alibaba Cloud SDK"
AUTHOR_EMAIL = "sdk-team@alibabacloud.com"
URL = "https://github.com/aliyun/alibabacloud-dkms-gcs-python2-sdk"
VERSION = "1.0.0"
REQUIRES = [
    "alibabacloud_openapi_util_py2>=0.1.1",
    "protobuf>=3.12.0,<=3.17.0",
    "alibabacloud_tea_util_py2>=0.0.1",
    "pyopenssl>=16.2.0,<=21.0.0",
    "cryptography<=3.3.2",
    "alibabacloud_darabonba_array_py2>=0.1.0",
    "alibabacloud_darabonba_stream_py2>=0.0.1",
    "alibabacloud_darabonba_string_py2>=0.0.4",
    "alibabacloud_darabonba_signature_util_py2>=0.0.4",
    "alibabacloud_darabonba_encode_util_py2>=0.0.2",
    "alibabacloud_darabonba_map_py2>=0.0.1",
    "alibabacloud_tea_util_py2>=0.0.9, <1.0.0"
]
LONG_DESCRIPTION = ''
if os.path.exists('./README.rst'):
    with open("README.rst") as fp:
        LONG_DESCRIPTION = fp.read()

setup(
    name=NAME,
    version=VERSION,
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    author=AUTHOR,
    author_email=AUTHOR_EMAIL,
    license="Apache License 2.0",
    url=URL,
    keywords=["alibabacloud", "dkms_gcs_sdk"],
    packages=find_packages(exclude=["example*"]),
    include_package_data=True,
    platforms="any",
    install_requires=REQUIRES,
    python_requires=">=2.7",
    classifiers=(
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Topic :: Software Development"
    )
)
