from .portal import PortalSession
from .rdp import (
    FreeRDPSession,
    RDPSessionSettings,
)
from .ui import UI
from .version import __version__

from dataclasses import dataclass
from pathlib import Path

import argparse
import os
import re
import sys
import yaml


USER_AGENT = "l3-remote-desktop/" + __version__


@dataclass
class Context:

    username: str = None
    password: str = None
    rsa_pin: str = None
    token: str = None
    domain: str = None
    smartcard_pin: str = None

    freerdp: str = "xfreerdp3"
    fullscreen: bool = False
    verbose: bool = False


def main():
    args = parse_args()

    if args.config is None:
        args.config = get_config_path()

    ui = UI()
    ctx = load_context(ui, args.config)

    if args.username:
        ctx.username = args.username
    if args.domain:
        ctx.domain = args.domain
    if args.freerdp:
        ctx.freerdp = args.freerdp
    if args.token:
        ctx.token = args.token
    if args.fullscreen:
        ctx.fullscreen = args.fullscreen
    if args.verbose:
        ctx.verbose = args.verbose

    if ctx.verbose:
        ui.set_debug(True)

    cache = get_cache_path()

    if not ctx.domain:
        ctx.domain = ui.input("Enter domain: ")

    session = PortalSession(domain=ctx.domain, cache=cache)
    session.set_user_agent(USER_AGENT)
    session.set_log_request_callback(ui.log_request)
    session.set_log_response_callback(ui.log_response)
    session.set_authentication_info_callback(LoadAuthenticationInfo(ui, ctx))

    try:
        rdp_settings = session.connect()
    except PortalSession.RDPRequestError:
        ui.fatal("Failed to authenticate.")

    if not ctx.smartcard_pin:
        ctx.smartcard_pin = ui.getpass("Enter smartcard pin: ")

    if ctx.fullscreen:
        rdp_settings.fullscreen = True
    rdp_settings.clipboard = True
    rdp_settings.floatbar = RDPSessionSettings.Floatbar(sticky=False)
    rdp_settings.security_protocol = RDPSessionSettings.SecurityProtocol.RDP
    rdp_settings.smartcard = RDPSessionSettings.Smartcard()
    rdp_settings.smartcard_logon = RDPSessionSettings.SmartcardLogon(
        pin=ctx.smartcard_pin
    )

    rdp_session = FreeRDPSession(rdp_settings, freerdp_exec=ctx.freerdp)

    ui.info("Launching RDP session.")
    ui.log_exec(sanitize_rdp_command(" ".join(rdp_session.command)))

    rdp_session.launch()


def get_config_path():
    config = Path("l3-remote-desktop/l3-remote-desktop.yml")

    if "XDG_CONFIG_HOME" in os.environ:
        return Path(os.environ["XDG_CONFIG_HOME"]) / config
    else:
        return Path("~/.config").expanduser() / config


def get_cache_path():
    cache = "l3-remote-desktop.json"

    if "XDG_CACHE_HOME" in os.environ:
        return Path(os.environ["XDG_CACHE_HOME"]) / cache
    else:
        return Path("~/.cache").expanduser() / cache


def load_context(ui, config):
    if not config.exists() or not config.is_file():
        return Context()

    with config.open() as f:
        try:
            data = yaml.safe_load(f.read())
        except yaml.scanner.ScannerError as e:
            print(e, file=sys.stderr)
            ui.fatal(f"Failed reading config: {config}")

    return Context(**data)


def sanitize_rdp_command(command: str):
    # Replace smartcard pin so it is not shown in plaintext.
    return re.sub(r"(/smartcard-logon:pin:)(\d+)", r"\1********", command)


class LoadAuthenticationInfo:
    def __init__(self, ui, ctx):
        self._ui = ui
        self._ctx = ctx

    def __call__(self):
        if self._ctx.username is None:
            self._ctx.username = self._ui.input("Enter username: ")
        if self._ctx.password is None:
            self._ctx.password = self._ui.getpass("Enter password: ")
        if self._ctx.rsa_pin is None:
            self._ctx.rsa_pin = self._ui.getpass("Enter RSA pin: ")
        if self._ctx.token is None:
            self._ctx.token = self._ui.input("Enter RSA token: ")

        return PortalSession.AuthenticationInfo(
            self._ctx.username,
            self._ctx.password,
            self._ctx.rsa_pin,
            self._ctx.token,
        )


def parse_args():
    parser = argparse.ArgumentParser(
        prog="L3Harris Remote Desktop",
        description="Authenticate with L3 portal and launch remote desktop session.",
    )

    parser.add_argument(
        "-c",
        "--config",
        type=Path,
        help="Path to configuration file. Default is `$XDG_CONFIG_HOME/l3-remote-desktop/l3-remote-desktop.yml`",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output."
    )
    parser.add_argument(
        "--freerdp", help="Name of FreeRDP executable. Default is `xfreerdp3`."
    )
    parser.add_argument("-u", "--username", help="L3 portal username (email address).")
    parser.add_argument("-d", "--domain", help="RDP domain (computer name).")
    parser.add_argument(
        "-f", "--fullscreen", action="store_true", help="Launch RDP session fullscreen."
    )
    parser.add_argument("-t", "--token", help="RSA Token.")

    return parser.parse_args()


if __name__ == "__main__":
    main()
