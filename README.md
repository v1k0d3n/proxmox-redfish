# Proxmox Redfish Daemon

[![CI/CD Pipeline](https://github.com/v1k0d3n/proxmox-redfish/workflows/CI%2FCD%20Pipeline/badge.svg)](https://github.com/v1k0d3n/proxmox-redfish/actions)
[![Coverage](https://img.shields.io/badge/coverage-85%25-green.svg)](https://github.com/v1k0d3n/proxmox-redfish/actions)[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/badge/release-v0.2.0-blue.svg)](https://github.com/v1k0d3n/proxmox-redfish/releases/tag/v0.2.0)

A Redfish API daemon for managing Proxmox VMs, providing a standardized interface for VM operations through the Redfish protocol. This enables integration with tools like Metal3, Ironic, OpenShift ACM ZTP/GitOps, and other Redfish-compatible management solutions.

## Table of Contents
- [Prerequisites](#prerequisites)
- [System Requirements](#system-requirements)
- [Quick Start Guide](#quick-start-guide)
   - [Installation](#installation)
   - [Creating a Least-Privilege Redfish Account](#creating-a-least-privilege-redfish-account)
- [Advanced Documentation](#advanced-documentation)
- [Validation Testing and Troubleshooting](#validation-testing-and-troubleshooting)
   - [Common Issues](#common-issues)
   - [Getting Help](#getting-help)
- [Security Notes](#security-notes)
- [License](#license)
- [Contributing](#contributing)
- [Background](#background)

## Prerequisites

- Proxmox VE 7.0 or higher
- Root access to your Proxmox host
- Internet connection for downloading dependencies

## System Requirements

- **Proxmox VE**: 7.0 or higher
- **Python**: 3.8 or higher
- **Memory**: 512MB RAM minimum
- **Storage**: 100MB free space
- **Network**: HTTP/HTTPS access to Proxmox API

## Quick Start Guide

This guide will take you from a fresh Proxmox installation to a fully working Redfish API daemon, even if you're not extremely comfortable with the Proxmox host-level Linux CLI.


### Installation

1. Make sure to upgrade your system before beginning. **Open a web browser** and navigate to your Proxmox web interface:

   ```bash
   https://your-proxmox-ip:8006
   ```

2. Navigate to **Datacenter** > **YOUR-HYPERVISOR-HOSTNAME** > **Updates**, and click on **Refresh** to update your that host's packages.

3. Connect to your Proxmox Hypervisor (example: **YOUR-HYPERVISOR-HOSTNAME**), with a user that has full administrative priveledges (example: `root`).

   ```bash
   ssh root@YOUR-HYPERVISOR-HOSTNAME
   ```

4. Install Python and Dependencies

   ```bash
   # Update the system
   apt update && apt upgrade -y

   # Install Python 3 and pip
   apt install -y python3 python3-pip python3-venv git jq

   # Install additional required packages
   apt install -y git openssl curl
   ```

5. Install the daemon

   The installer creates a virtual environment, installs the package into it,
   generates a self-signed certificate, writes a configuration template and a
   systemd unit, and stops there. Nothing starts until you have filled in the
   configuration.

   ```bash
   git clone https://github.com/v1k0d3n/proxmox-redfish.git /tmp/proxmox-redfish
   /tmp/proxmox-redfish/scripts/install.sh
   ```

   To install a particular release rather than the default branch:

   ```bash
   /tmp/proxmox-redfish/scripts/install.sh --version v0.2.0
   ```

   Useful options: `--install-dir` to install elsewhere, `--skip-service` to
   install the package without touching systemd, `--yes` to answer prompts.

   A virtual environment is not optional. Proxmox does not carry `proxmoxer`
   or `requests` system-wide, and installing them into the system Python with
   pip is not safe on a Debian host.

   <details>
   <summary>Installing by hand instead</summary>

   ```bash
   mkdir -p /opt/proxmox-redfish/config/ssl
   python3 -m venv /opt/proxmox-redfish/venv
   /opt/proxmox-redfish/venv/bin/pip install \
     git+https://github.com/v1k0d3n/proxmox-redfish.git
   ```

   That gives you `/opt/proxmox-redfish/venv/bin/proxmox-redfish`. The
   certificate, `config/params.env` and the systemd unit are then yours to
   create; the steps below show what the installer would have written.
   </details>

   > **Replacing an earlier version.** This release is structured differently
   > from anything before `v0.2.0` -- the daemon was a single script and is now
   > an installed package. There is no in-place upgrade. Back up the old
   > directory and its unit file, then install fresh:
   >
   > ```bash
   > tar czf /root/proxmox-redfish-backup.tgz -C /opt proxmox-redfish
   > cp /etc/systemd/system/proxmox-redfish.service /root/
   > ```
   >
   > Read "Upgrading from a release before caller identity" in the
   > [Administrators Guide](./docs/admins/README.md#proxmox-permissions) first.
   > Requests are now served using the calling account's own Proxmox
   > credentials, so those accounts need privileges before they will work.

6. Optional (recommended): Generate basic SSL certificates - these can be valid certs, if you want to generate them a different way (below is primarily a working example)

   **WARNING:** *For all you copy/paste warriors out there, be sure to check out the [Administrators Guide](./docs/admins/README.md#ssl-configuration) for better certificate options (including [Let's Encrypt](./docs/admins/README.md#lets-encrypt-certificate-production) options).*
   ```bash
   # Ensure this directory exists - it should already exists
   mkdir -p /opt/proxmox-redfish/config/ssl

   # Generate a self-signed certificate (for testing)
   openssl req -x509 -newkey rsa:4096 -keyout /opt/proxmox-redfish/config/ssl/server.key -out /opt/proxmox-redfish/config/ssl/server.crt -days 365 -nodes -subj "/CN=$(hostname)"

   # Set proper permissions
   chmod 600 /opt/proxmox-redfish/config/ssl/server.key
   chmod 644 /opt/proxmox-redfish/config/ssl/server.crt
   ```

7. Configure the proxmox-redfish daemon:

   Create a configuration file:
   ```bash
   # Find the values to use:
   #   hostname -I | awk '{print $1}'    -> address for PROXMOX_HOST
   #   hostname                          -> node name for PROXMOX_NODE
   #
   # Write the results below as literal values. This file is read by systemd,
   # which does not run commands, so a $(...) written here is taken as the
   # host's name rather than being replaced by its output.
   cat > /opt/proxmox-redfish/config/params.env << 'EOF'
   # Proxmox Configuration
   PROXMOX_HOST="10.0.0.5"
   # No Proxmox account is configured here. Each request is served using the
   # credentials of the Redfish caller, so the daemon holds no account of its
   # own. Grant privileges to the calling accounts instead -- see "Proxmox
   # Permissions" in docs/admins.
   PROXMOX_API_PORT="8006"
   PROXMOX_NODE="pve"
   PROXMOX_ISO_STORAGE="local"

   # SSL Configuration
   SSL_CERT_FILE="/opt/proxmox-redfish/config/ssl/server.crt"
   SSL_KEY_FILE="/opt/proxmox-redfish/config/ssl/server.key"

   # Logging Configuration
   REDFISH_LOG_LEVEL="INFO"
   REDFISH_LOGGING_ENABLED="true"

   # SSL Verification (for Proxmox API)
   VERIFY_SSL="false"
   EOF
   ```
   **Important**: Replace `your-proxmox-root-password` with your actual Proxmox root password.

8. Create a systemd service unit, if you installed by hand

   The installer writes this for you. The port comes from `REDFISH_PORT` in
   `params.env`, so it is not repeated here.

   ```bash
   # Create the systemd service file
   cat > /etc/systemd/system/proxmox-redfish.service << 'EOF'
   [Unit]
   Description=Proxmox Redfish Daemon
   After=network.target

   [Service]
   Type=simple
   User=root
   Group=root
   WorkingDirectory=/opt/proxmox-redfish
   EnvironmentFile=/opt/proxmox-redfish/config/params.env
   ExecStart=/opt/proxmox-redfish/venv/bin/proxmox-redfish
   Restart=always
   RestartSec=10

   [Install]
   WantedBy=multi-user.target
   EOF

   # Ensure the following permissions on the service file
   chmod 644 /etc/systemd/system/proxmox-redfish.service

   # Reload systemd and enable the service
   systemctl daemon-reload
   systemctl enable proxmox-redfish.service --now
   ```

9. Start the service

   ```bash
   # Start the service
   systemctl start proxmox-redfish

   # Check if it's running
   systemctl status proxmox-redfish

   # View the logs
   journalctl -u proxmox-redfish -f
   ```

### Creating a Least-Privilege Redfish Account

The daemon holds no Proxmox account of its own. Every request is performed
using the credentials of the caller, so what a caller can do is decided by
their Proxmox permissions. Create an account for whatever will drive the
daemon, and grant it only what it needs:

1. In the Proxmox web interface
   - Go to "Datacenter" → **Users**
   - Click "Add" → **User**
   - Create a user like `redfish@pam`
   - Set a strong password

2. Update the configuration

   ```bash
   # Edit the configuration file
   vi /opt/proxmox-redfish/config/params.env
   
   # The daemon holds no Proxmox account. Grant privileges to the accounts
   # that will call the Redfish API instead -- see "Proxmox Permissions" in
   # docs/admins.
   ```

3. Restart the service

   ```bash
   systemctl restart proxmox-redfish
   ```

## Advanced Documentation

There are a few guides that users may find useful:
- **For Users**: See the [User Guide](docs/users/README.md) for Redfish API usage
- **For Administrators**: See the [Admin Guide](docs/admins/README.md) for configuration and security
- **For Developers**: See [Contributor Guide](docs/contrib/README.md) for development and testing

## Validation Testing and Troubleshooting

A user-guide has been provided to assist with basic testing and vailidating your deployment. See the [User Guide](docs/users/README.md) for more detail.

### Common Issues

1. **Service won't start**
   ```bash
   # Check the logs
   journalctl -u proxmox-redfish -n 50
   
   # Check if the virtual environment is activated
   ls -la /opt/proxmox-redfish/venv/bin/python
   ```

2. **SSL certificate errors**
   ```bash
   # Regenerate the certificate
   cd /opt/proxmox-redfish
   openssl req -x509 -newkey rsa:4096 -keyout config/ssl/server.key -out config/ssl/server.crt -days 365 -nodes -subj "/CN=$(hostname)"
   chmod 600 config/ssl/server.key
   chmod 644 config/ssl/server.crt
   systemctl restart proxmox-redfish
   ```

3. **Authentication errors**
   - Verify your Proxmox credentials in `config/params.env`
   - Check that the user has appropriate permissions
   - Ensure the Proxmox host is accessible

4. **Advanced logging**
   - This project uses a crude Linux logging level to monitor Redfish calls to the daemon process. If you want to change the default logging level the `params.env` file. (example: change `REDFISH_LOG_LEVEL="INFO"` to `REDFISH_LOG_LEVEL="DEBUG"`).

### Getting Help

- Check the [Admin Guide](docs/admins/README.md) for detailed configuration options
- Review the [User Guide](docs/users/README.md) for API usage examples
- Open an issue on GitHub for bugs or feature requests (I'm always looking for input or new ideas)

## Security Notes

- The daemon runs as root by default for full VM access (you may change this to a [PoLP](https://en.wikipedia.org/wiki/Principle_of_least_privilege) model if desired)
- SSL certificates are self-signed by default (you can provide your own valid certificates if desired)
- Consider using a dedicated user with limited permissions (through Roles/Permissions in Proxmox)
- Always keep your Proxmox credentials secure
- Regularly update the daemon and dependencies (as this project matures over time)

## License

This project is licensed under the Apache 2.0 - see the [LICENSE](LICENSE) file for details.

## Contributing

I'm definitely looking for feedback and contibutions! Please see the [Contributor Guide](docs/contrib/README.md) for details on how to get started. 

## Background

This project was _heavily_ influenced from project originally started by [jorgeventura](https://github.com/jorgeventura/pve-redfish), but what started out as one script with many remaining gaps turned into something way too large to contribute back. I will however contact the original author and see if there's an opportunity to colaborate going forward, but I felt like I needed to show intent first. I used [Cursor](https://cursor.com/?from=home) to draft the original framework for this project, and as a result, there's quite a bit of work to do in order to make things a bit more clean. But a turn-around of less than 24hrs for something that would take me a month to complete isn't half-bad.

Please feel free to leave an [ISSUE](https://github.com/v1k0d3n/proxmox-redfish/issues) or submit a [PR](https://github.com/v1k0d3n/proxmox-redfish/pulls) if you have any input that you would like to share.
