from dataclasses import dataclass
from enum import StrEnum

import subprocess


class RDPSessionSettings:

    class SecurityProtocol(StrEnum):
        RDP = "rdp"
        TLS = "tls"
        NLA = "nla"
        EXT = "ext"
        AAD = "aad"

    @dataclass
    class Gateway:
        gateway: str = None
        access_token: str = None
        user: str = None
        password: str = None
        domain: str = None

    @dataclass
    class Floatbar:

        class Visibility(StrEnum):
            VISIBLE = "visible"
            HIDDEN = "hidden"

        class Show(StrEnum):
            ALWAYS = "always"
            FULLSCREEN = "fullscreen"
            WINDOW = "window"

        sticky: bool = False
        # Corresponds to /floatbar:default xfreerdp argument.
        visibility: Visibility = None
        show: Show = None

    @dataclass
    class Smartcard:
        # Redirect the smartcard devices containing any of the <str> in their
        # names `man 1 xfreerdp3`.
        devices: list[str] = None

    @dataclass
    class SmartcardLogon:
        pin: str = None

    def __init__(self):
        self.user: str = None
        self.server: str = None
        self.port: int = None
        self.domain: str = None
        self.fullscreen: bool = False
        self.clipboard: bool = False
        self.security_protocol: self.SecurityProtocol = None
        self.smartcard: self.Smartcard = None
        self.smartcard_logon: self.SmartcardLogon = None
        self.gateway: self.Gateway = None
        self.floatbar: self.Floatbar = None


class RDPParser:

    TYPE_INT = "i"
    TYPE_STR = "s"

    @classmethod
    def parse(cls, content: str) -> RDPSessionSettings:
        settings = RDPSessionSettings()
        settings.gateway = RDPSessionSettings.Gateway()

        for line in content.splitlines():
            # Each line should have <setting>:<type>:<value>.
            # Type is either "i" for integer or "s" for string.
            fields = line.split(":")
            if len(fields) != 3:
                continue

            key, type, value = fields
            if type == cls.TYPE_INT:
                value = int(value)

            match key:
                case "full address":
                    settings.server = value
                case "gatewayaccesstoken":
                    settings.gateway.access_token = value
                case "gatewayhostname":
                    settings.gateway.gateway = value
                case "server port":
                    settings.port = value

        return settings


class FreeRDPSession:

    def __init__(self, settings: RDPSessionSettings, freerdp_exec="xfreerdp3"):
        self._settings = settings
        self._command = None
        self._freerdp_exec = freerdp_exec

    @property
    def command(self):
        if self._command is None:
            self._command = self._generate_command()
        return self._command

    def _generate_command(self):
        cmd = [self._freerdp_exec]

        self._settings.fullscreen and cmd.append("/f")
        self._settings.clipboard and cmd.append("/clipboard")

        floatbar = self._get_floatbar_argument()
        floatbar and cmd.append(floatbar)

        if self._settings.security_protocol:
            cmd.append("/sec:" + self._settings.security_protocol.value)

        smartcard = self._get_smartcard_argument()
        smartcard and cmd.append(smartcard)

        smartcard_logon = self._get_smartcard_logon_argument()
        smartcard_logon and cmd.append(smartcard_logon)

        self._settings.user and cmd.append("/u:" + self._settings.user)
        self._settings.server and cmd.append("/v:" + self._settings.server)
        self._settings.port and cmd.append("/port:" + str(self._settings.port))
        self._settings.domain and cmd.append("/d:" + self._settings.domain)

        gateway = self._get_gateway_argument()
        gateway and cmd.append(gateway)

        return cmd

    def _get_gateway_argument(self):
        if self._settings.floatbar is None:
            return None

        args = []
        gateway = self._settings.gateway

        gateway.gateway and args.append("g:" + gateway.gateway)
        gateway.access_token and args.append("access-token:" + gateway.access_token)
        gateway.user and args.append("u:" + gateway.user)
        gateway.password and args.append("p:" + gateway.password)
        gateway.domain and args.append("d:" + gateway.domain)

        if not args:
            return None

        return "/gateway:" + ",".join(args)

    def _get_floatbar_argument(self):
        if self._settings.floatbar is None:
            return None

        args = []
        floatbar = self._settings.floatbar

        if floatbar.sticky is not None:
            args.append("sticky:" + ("on" if floatbar.sticky else "off"))

        if floatbar.visibility is not None:
            args.append("default:" + floatbar.visibility.value)

        if floatbar.show is not None:
            args.append("show:" + floatbar.show.value)

        if not args:
            return None

        return "/floatbar:" + ",".join(args)

    def _get_smartcard_argument(self):
        if self._settings.smartcard is None:
            return None

        smartcard = self._settings.smartcard
        arg = "/smartcard"
        if smartcard.devices:
            arg += ":" + ",".join(smartcard.devices)

        return arg

    def _get_smartcard_logon_argument(self):
        if self._settings.smartcard_logon is None:
            return None

        smartcard_logon = self._settings.smartcard_logon
        args = []

        smartcard_logon.pin and args.append("pin:" + smartcard_logon.pin)

        arg = "/smartcard-logon"
        if args:
            arg += ":" + ",".join(args)

        return arg

    def launch(self):
        p = subprocess.Popen(self.command)
        p.wait()
