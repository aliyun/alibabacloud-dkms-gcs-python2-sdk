# -*- coding: utf-8 -*-
import base64
import os

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from openapi.models import Config
from sdk.client import Client
from sdk.models import DecryptRequest, GenerateDataKeyPairResponse, \
    GenerateDataKeyPairRequest

config = Config()
config.protocol = "https"
config.client_key_file = "<your-client-key-file>"
config.password = os.getenv('CLIENT_KEY_PASSWORD')
config.endpoint = "<your-endpoint>"
config.ca_file_path = "<your-ca-certificate-file-path>"
client = Client(config)

KEY_FORMAT_DER = "DER"
KEY_FORMAT_PEM = "PEM"


class KeyPairInfo(object):

    def __init__(
            self,
            key_id,
            iv,
            key_pair_spec,
            private_key_ciphertext_blob,
            public_key,
            algorithm,
            key_format
    ):
        self.key_id = key_id
        self.iv = iv
        self.key_pair_spec = key_pair_spec
        self.private_key_ciphertext_blob = private_key_ciphertext_blob
        self.public_key = public_key
        self.algorithm = algorithm
        self.key_format = key_format


def generate_data_key_pair(
        key_format,
        key_id,
        key_pair_spec,
):
    request = GenerateDataKeyPairRequest(
        key_format=key_format,
        key_id=key_id,
        key_pair_spec=key_pair_spec
    )
    return client.generate_data_key_pair(request)


def decrypt(key_id, iv, ciphertext_blob):
    request = DecryptRequest()
    request.ciphertext_blob = ciphertext_blob
    request.key_id = key_id
    request.iv = iv
    resp = client.decrypt(request)
    return resp.plaintext


def save_key_pair_info(generate_data_key_pair_response, key_format):
    key_pair_info = KeyPairInfo(generate_data_key_pair_response.key_id, generate_data_key_pair_response.iv,
                                generate_data_key_pair_response.key_pair_spec,
                                generate_data_key_pair_response.private_key_ciphertext_blob,
                                generate_data_key_pair_response.public_key,
                                generate_data_key_pair_response.algorithm, key_format)
    # TODO 此处可以持久化公钥及私钥密文等信息
    return key_pair_info


def sign(private_key, data):
    return private_key.sign(data, padding.PSS(padding.MGF1(hashes.SHA256()),
                                              padding.PSS.MAX_LENGTH),
                            hashes.SHA256())


def verify(public_key, data, signature):
    return public_key.verify(signature, data, padding.PSS(padding.MGF1(hashes.SHA256()),
                                                          padding.PSS.MAX_LENGTH),
                             hashes.SHA256())


key_format = KEY_FORMAT_DER
key_id = "<your-key-id>"
key_pair_spec = "<your-key-pair-spec>"
generate_data_key_pair_response = generate_data_key_pair(key_format, key_id, key_pair_spec)
key_pair_info = save_key_pair_info(generate_data_key_pair_response, key_format)
# 签名
private_key_ciphertext_blob = base64.b64decode(key_pair_info.private_key_ciphertext_blob)
iv = key_pair_info.iv
private_key_plaintext = decrypt(key_pair_info.key_id, key_pair_info.iv, key_pair_info.private_key_ciphertext_blob)
message = "your-message".encode("utf-8")
private_key = None
if key_pair_info.key_format == KEY_FORMAT_PEM:
    private_key = serialization.load_pem_private_key(private_key_plaintext, None)
elif key_pair_info.key_format == KEY_FORMAT_DER:
    private_key = serialization.load_der_private_key(private_key_plaintext, None)
else:
    raise ValueError("not found key_format %s" % key_pair_info.key_format)

signature = sign(private_key, message)

# 验签
public_key = None
if key_pair_info.key_format == KEY_FORMAT_PEM:
    public_key = serialization.load_pem_public_key(key_pair_info.public_key)
elif key_pair_info.key_format == KEY_FORMAT_DER:
    public_key = serialization.load_der_public_key(key_pair_info.public_key)
else:
    raise ValueError("not found key_format %s" % key_pair_info.key_format)
verify(public_key, message, signature)
