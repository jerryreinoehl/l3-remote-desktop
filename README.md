# l3-remote-desktop

Authenticate with L3 portal and launch remote desktop session.


## Dependencies

* `python3`
* `python3-requests`
* `freerdp`
* `ccid` (Smartcard)
* `opensc` (Smartcard)
* `pcsclite` (Smartcard)


## Configuration

Configuration is read from
`$XDG_CONFIG_HOME/l3-remote-desktop/l3-remote-desktop.yml`. If the
`XDG_CONFIG_HOME` environment variable is not set then configuration is read
from `~/.config/l3-remote-desktop/l3-remote-desktop.yml`.
The configuration file can be overridden with the `-c` or `--config` argument.

### Configuration Options

* `username: str`: L3 portal username (email address).
* `password: str`: L3 portal password.
* `rsa_pin: str`: RSA PIN.
* `domain: str`: RDP domain (computer name).
* `smartcard_pin: str`: Smartcard PIN.
* `freerdp: str`: FreeRDP executable (defaults to `xfreerdp3`).
* `fullscreen: bool`: Launch RDP in fullscreen mode.
* `verbose: bool`: Enable verbose output.


## Smartcard Configuration

### Arch Linux

Install `ccid`, `opensc`, and `pcsclite`.

```
sudo pacman -Syu
sudo pacman -S ccid opensc pcsclite
```

Enable `pcscd.socket`.

```
sudo systemctl enable --now pcscd.socket
```

See [Smartcards](https://wiki.archlinux.org/title/Smartcards) for more info and
troubleshooting.
