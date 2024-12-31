from .rdp import RDPParser

from dataclasses import dataclass
from pathlib import Path

import base64
import getpass
import json
import requests


class PortalSession:

    class PortalSessionError(RuntimeError): ...

    class InitializationError(PortalSessionError): ...

    class AuthenticationError(PortalSessionError): ...

    class RDPRequestError(PortalSessionError): ...

    @dataclass
    class AuthenticationInfo:
        username: str
        password: str
        pin: str
        token: str
        vhost: str = "standard"

    def __init__(self, domain, cache: Path = None):
        self._session = requests.Session()
        self._domain = domain
        self._cache = cache
        self._log_req_cb = None
        self._log_res_cb = None
        self._authentication_info_cb = self._get_authentication_info

    def _get_authentication_info(self):
        username = input("Username: ")
        password = getpass.getpass("Password: ")
        pin = getpass.getpass("Pin: ")
        token = input("Token: ")

        return self.AuthenticationInfo(username, password, pin, token)

    def set_user_agent(self, user_agent: str):
        self._session.headers["User-Agent"] = user_agent

    def log_request(self, request):
        if not self._log_req_cb:
            return

        self._log_req_cb(f"{request.method} {request.url}")
        for k, v in request.headers.items():
            self._log_req_cb(f"{k}: {v}")

    def log_response(self, response, log_content=False):
        if not self._log_res_cb:
            return

        self._log_res_cb(f"[{response.status_code} {response.reason}] {response.url}")
        for k, v in response.headers.items():
            self._log_res_cb(f"{k}: {v}")

        if log_content and len(response.content) > 0:
            self._log_res_cb("")
            for line in response.content.decode().splitlines():
                self._log_res_cb(line)

    def set_log_request_callback(self, log_req_cb):
        self._log_req_cb = log_req_cb

    def set_log_response_callback(self, log_res_cb):
        self._log_res_cb = log_res_cb

    def set_authentication_info_callback(self, authentication_info_cb):
        self._authentication_info_cb = authentication_info_cb

    def initialize(self):
        url = "https://portal.l3t.com/"

        req = requests.Request("GET", url)
        req = self._session.prepare_request(req)

        self.log_request(req)

        res = self._session.send(req)

        self.log_response(res)

        if not res.ok:
            raise self.InitializationError()

    def authenticate(self):
        url = "https://portal.l3t.com/my.policy"
        auth = self._authentication_info_cb()

        data = dict(
            username=auth.username,
            password=auth.password,
            rsapassword=auth.pin + auth.token,
            vhost=auth.vhost,
        )

        req = requests.Request("POST", url, data=data)
        req = self._session.prepare_request(req)

        self.log_request(req)
        res = self._session.send(req)
        self.log_response(res)

        if not res.ok:
            raise self.AuthenticationError()

    def request_rdp_session(self):
        domain_b64 = base64.b64encode(bytes(self._domain, "utf-8")).decode()
        url = f"https://portal.l3t.com/f5vdi/rdp/launch/Portal_L3T/Enterprise_Remote_Desktop?{domain_b64}"

        req = requests.Request("GET", url)
        req = self._session.prepare_request(req)

        self.log_request(req)
        res = self._session.send(req)
        self.log_response(res, log_content=True)

        if not res.ok:
            raise self.RDPRequestError()

        return RDPParser.parse(res.content.decode())

    def _load_cache(self):
        is_cache_valid = (
            self._cache and self._cache.exists() and self._cache.is_file()
        )

        if not is_cache_valid:
            return False

        with self._cache.open() as f:
            try:
                cookies = json.loads(f.read())
                self._session.cookies.update(
                    requests.utils.cookiejar_from_dict(cookies)
                )
            except json.decoder.JSONDecodeError:
                return False

        return True

    def _save_cache(self):
        if not self._cache:
            return

        with self._cache.open("w") as f:
            f.write(json.dumps(self._session.cookies.get_dict()))

    def connect(self):
        if self._load_cache():
            try:
                return self.request_rdp_session()
            except self.RDPRequestError:
                self._session.cookies.clear()

        self.initialize()
        self.authenticate()

        self._save_cache()

        return self.request_rdp_session()
