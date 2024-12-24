# l3-remote-desktop

Authenticate with L3 portal and launch remote desktop session.


## Configuration

Configuration is read from
`$XDG_CONFIG_HOME/l3-remote-desktop/l3-remote-desktop.yml`. If the
`XDG_CONFIG_HOME` environment variable is not set then configuration is read
from `~/.config/l3-remote-desktop/l3-remote-desktop.yml`.

### Configuration Options

* `username`: L3 portal username (email address).
* `password`: L3 portal password.
* `rsa_pin`: RSA PIN.
* `domain`: RDP domain (computer name).
* `smartcard_pin`: Smartcard PIN.
* `freerdp`: FreeRDP executable (defaults to `xfreerdp3`).
* `fullscreen`: Launch RDP in fullscreen mode.
* `verbose`: Enable verbose output.
