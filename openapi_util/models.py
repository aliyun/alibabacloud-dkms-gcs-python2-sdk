# -*- coding: utf-8 -*-
# This file is auto-generated, don't edit it. Thanks.
from Tea.model import TeaModel


class RuntimeOptions(TeaModel):
    def __init__(self, autoretry=None, ignore_ssl=None, max_attempts=None, backoff_policy=None, backoff_period=None,
                 read_timeout=None, connect_timeout=None, http_proxy=None, https_proxy=None, no_proxy=None, max_idle_conns=None,
                 socks_5proxy=None, socks_5net_work=None, verify=None, response_headers=None):
        # 是否自动重试
        self.autoretry = autoretry  # type: bool
        # 是否忽略SSL认证
        self.ignore_ssl = ignore_ssl  # type: bool
        # 最大重试次数
        self.max_attempts = max_attempts  # type: int
        # 回退策略
        self.backoff_policy = backoff_policy  # type: str
        # 回退周期
        self.backoff_period = backoff_period  # type: int
        # 读取超时时间
        self.read_timeout = read_timeout  # type: int
        # 连接超时时间
        self.connect_timeout = connect_timeout  # type: int
        # http代理
        self.http_proxy = http_proxy  # type: str
        # https代理
        self.https_proxy = https_proxy  # type: str
        # 无代理
        self.no_proxy = no_proxy  # type: str
        # 最大闲置连接数
        self.max_idle_conns = max_idle_conns  # type: int
        # socks5代理
        self.socks_5proxy = socks_5proxy  # type: str
        # socks5代理协议
        self.socks_5net_work = socks_5net_work  # type: str
        # 校验
        self.verify = verify  # type: str
        # 响应头
        self.response_headers = response_headers  # type: list[str]

    def validate(self):
        pass

    def to_map(self):
        _map = super(RuntimeOptions, self).to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.autoretry is not None:
            result['autoretry'] = self.autoretry
        if self.ignore_ssl is not None:
            result['ignoreSSL'] = self.ignore_ssl
        if self.max_attempts is not None:
            result['maxAttempts'] = self.max_attempts
        if self.backoff_policy is not None:
            result['backoffPolicy'] = self.backoff_policy
        if self.backoff_period is not None:
            result['backoffPeriod'] = self.backoff_period
        if self.read_timeout is not None:
            result['readTimeout'] = self.read_timeout
        if self.connect_timeout is not None:
            result['connectTimeout'] = self.connect_timeout
        if self.http_proxy is not None:
            result['httpProxy'] = self.http_proxy
        if self.https_proxy is not None:
            result['httpsProxy'] = self.https_proxy
        if self.no_proxy is not None:
            result['noProxy'] = self.no_proxy
        if self.max_idle_conns is not None:
            result['maxIdleConns'] = self.max_idle_conns
        if self.socks_5proxy is not None:
            result['socks5Proxy'] = self.socks_5proxy
        if self.socks_5net_work is not None:
            result['socks5NetWork'] = self.socks_5net_work
        if self.verify is not None:
            result['verify'] = self.verify
        if self.response_headers is not None:
            result['responseHeaders'] = self.response_headers
        return result

    def from_map(self, m=None):
        m = m or dict()
        if m.get('autoretry') is not None:
            self.autoretry = m.get('autoretry')
        if m.get('ignoreSSL') is not None:
            self.ignore_ssl = m.get('ignoreSSL')
        if m.get('maxAttempts') is not None:
            self.max_attempts = m.get('maxAttempts')
        if m.get('backoffPolicy') is not None:
            self.backoff_policy = m.get('backoffPolicy')
        if m.get('backoffPeriod') is not None:
            self.backoff_period = m.get('backoffPeriod')
        if m.get('readTimeout') is not None:
            self.read_timeout = m.get('readTimeout')
        if m.get('connectTimeout') is not None:
            self.connect_timeout = m.get('connectTimeout')
        if m.get('httpProxy') is not None:
            self.http_proxy = m.get('httpProxy')
        if m.get('httpsProxy') is not None:
            self.https_proxy = m.get('httpsProxy')
        if m.get('noProxy') is not None:
            self.no_proxy = m.get('noProxy')
        if m.get('maxIdleConns') is not None:
            self.max_idle_conns = m.get('maxIdleConns')
        if m.get('socks5Proxy') is not None:
            self.socks_5proxy = m.get('socks5Proxy')
        if m.get('socks5NetWork') is not None:
            self.socks_5net_work = m.get('socks5NetWork')
        if m.get('verify') is not None:
            self.verify = m.get('verify')
        if m.get('responseHeaders') is not None:
            self.response_headers = m.get('responseHeaders')
        return self


class ErrorResponse(TeaModel):
    def __init__(self, status_code=None, error_code=None, error_message=None, request_id=None):
        self.status_code = status_code  # type: str
        self.error_code = error_code  # type: str
        self.error_message = error_message  # type: str
        self.request_id = request_id  # type: str

    def validate(self):
        self.validate_required(self.status_code, 'status_code')
        self.validate_required(self.error_code, 'error_code')
        self.validate_required(self.error_message, 'error_message')
        self.validate_required(self.request_id, 'request_id')

    def to_map(self):
        _map = super(ErrorResponse, self).to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.status_code is not None:
            result['StatusCode'] = self.status_code
        if self.error_code is not None:
            result['ErrorCode'] = self.error_code
        if self.error_message is not None:
            result['ErrorMessage'] = self.error_message
        if self.request_id is not None:
            result['RequestId'] = self.request_id
        return result

    def from_map(self, m=None):
        m = m or dict()
        if m.get('StatusCode') is not None:
            self.status_code = m.get('StatusCode')
        if m.get('ErrorCode') is not None:
            self.error_code = m.get('ErrorCode')
        if m.get('ErrorMessage') is not None:
            self.error_message = m.get('ErrorMessage')
        if m.get('RequestId') is not None:
            self.request_id = m.get('RequestId')
        return self


