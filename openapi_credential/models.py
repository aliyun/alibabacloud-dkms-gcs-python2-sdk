# -*- coding: utf-8 -*-
# This file is auto-generated, don't edit it. Thanks.
from Tea.model import TeaModel


class Config(TeaModel):
    def __init__(self, type=None, access_key_id=None, private_key=None, client_key_file=None,
                 client_key_content=None, password=None):
        # 访问凭证类型
        self.type = type  # type: str
        # 访问凭证ID
        self.access_key_id = access_key_id  # type: str
        # pkcs1 或 pkcs8 PEM 格式私钥
        self.private_key = private_key  # type: str
        # ClientKey文件路径
        self.client_key_file = client_key_file  # type: str
        # ClientKey文件内容
        self.client_key_content = client_key_content  # type: str
        # ClientKey密码
        self.password = password  # type: str

    def validate(self):
        self.validate_required(self.type, 'type')

    def to_map(self):
        _map = super(Config, self).to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.type is not None:
            result['Type'] = self.type
        if self.access_key_id is not None:
            result['Type'] = self.access_key_id
        if self.private_key is not None:
            result['Type'] = self.private_key
        if self.client_key_file is not None:
            result['Type'] = self.client_key_file
        if self.client_key_content is not None:
            result['Type'] = self.client_key_content
        if self.password is not None:
            result['Type'] = self.password
        return result

    def from_map(self, m=None):
        m = m or dict()
        if m.get('Type') is not None:
            self.type = m.get('Type')
        if m.get('Type') is not None:
            self.access_key_id = m.get('Type')
        if m.get('Type') is not None:
            self.private_key = m.get('Type')
        if m.get('Type') is not None:
            self.client_key_file = m.get('Type')
        if m.get('Type') is not None:
            self.client_key_content = m.get('Type')
        if m.get('Type') is not None:
            self.password = m.get('Type')
        return self


class RsaKeyPairCredentials(TeaModel):
    def __init__(self, private_key_secret=None, key_id=None):
        # 访问凭证私钥
        self.private_key_secret = private_key_secret  # type: str
        # 访问凭证ID
        self.key_id = key_id  # type: str

    def validate(self):
        pass

    def to_map(self):
        _map = super(RsaKeyPairCredentials, self).to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.private_key_secret is not None:
            result['privateKeySecret'] = self.private_key_secret
        if self.key_id is not None:
            result['keyId'] = self.key_id
        return result

    def from_map(self, m=None):
        m = m or dict()
        if m.get('privateKeySecret') is not None:
            self.private_key_secret = m.get('privateKeySecret')
        if m.get('keyId') is not None:
            self.key_id = m.get('keyId')
        return self


