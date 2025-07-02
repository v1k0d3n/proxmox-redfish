# Administrator Guide - Deployment and Configuration

This guide is for system administrators who deploy, configure, and maintain the Proxmox Redfish Daemon. It covers installation, configuration, security, SSL setup, user management, and troubleshooting.

## Installation Options

For installation options, please review the [Quick Start Guide](../../README.md#installation) provided in the project's main [README](../../README.md).

## Configuration Options

### Environment Variables

The daemon can be configured using environment variables. Here are all available options:

#### Proxmox Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXMOX_HOST` | `pve-node-hostname` | Proxmox hostname or IP address |
| `PROXMOX_USER` | `username` | Proxmox username (i.e., `root@pam`) |
| `PROXMOX_PASSWORD` | `password` | Proxmox password or API token |
| `PROXMOX_NODE` | `pve-node-name` | Proxmox node name |
| `PROXMOX_ISO_STORAGE` | `local` | Storage pool for ISO downloads |
| `VERIFY_SSL` | `false` | Verify SSL certificates for Proxmox API |

#### Redfish Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `REDFISH_PORT` | `8443` | Port for the Redfish daemon |
| `REDFISH_HOST` | `0.0.0.0` | Host to bind the daemon to |

#### SSL Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SSL_CERT_FILE` | `/opt/redfish_daemon/config/ssl/server.crt` | SSL certificate file path |
| `SSL_KEY_FILE` | `/opt/redfish_daemon/config/ssl/server.key` | SSL private key file path |
| `SSL_CA_FILE` | `/opt/redfish_daemon/config/ssl/ca.crt` | CA certificate bundle (optional) |

#### Logging Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `REDFISH_LOG_LEVEL` | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL) |
| `REDFISH_LOGGING_ENABLED` | `true` | Enable/disable logging |

### Configuration File

Create a configuration file for easier management:

```bash
# Create configuration directory
mkdir -p /opt/proxmox-redfish/config

# Create configuration file
cat > /opt/proxmox-redfish/config/params.env << 'EOF'
# Proxmox Configuration
export PROXMOX_HOST="192.168.1.100"
export PROXMOX_USER="redfish@pam"
export PROXMOX_PASSWORD="your-secure-password"
export PROXMOX_NODE="pve"
export PROXMOX_ISO_STORAGE="local"
export VERIFY_SSL="false"

# Redfish Configuration
export REDFISH_PORT="8443"
export REDFISH_HOST="0.0.0.0"

# SSL Configuration
export SSL_CERT_FILE="/opt/proxmox-redfish/config/ssl/server.crt"
export SSL_KEY_FILE="/opt/proxmox-redfish/config/ssl/server.key"
export SSL_CA_FILE="/opt/proxmox-redfish/config/ssl/ca.crt"

# Logging Configuration
export REDFISH_LOG_LEVEL="INFO"
export REDFISH_LOGGING_ENABLED="true"
EOF
```

### JSON Configuration File

For more complex configurations, use JSON format:

```bash
cat > /opt/proxmox-redfish/config/config.json << 'EOF'
{
  "proxmox": {
    "host": "192.168.1.100",
    "user": "redfish@pam",
    "password": "your-secure-password",
    "node": "pve",
    "iso_storage": "local",
    "verify_ssl": false
  },
  "redfish": {
    "port": 8443,
    "host": "0.0.0.0",
    "ssl_cert": "/opt/proxmox-redfish/config/ssl/server.crt",
    "ssl_key": "/opt/proxmox-redfish/config/ssl/server.key",
    "ssl_ca": "/opt/proxmox-redfish/config/ssl/ca.crt"
  },
  "logging": {
    "level": "INFO",
    "enabled": true
  }
}
EOF
```

## SSL Configuration

### Self-Signed Certificate (Development/Testing)

```bash
# Create SSL directory
mkdir -p /opt/proxmox-redfish/config/ssl

# Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 \
  -keyout /opt/proxmox-redfish/config/ssl/server.key \
  -out /opt/proxmox-redfish/config/ssl/server.crt \
  -days 365 -nodes \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=$(hostname)"

# Set proper permissions
chmod 600 /opt/proxmox-redfish/config/ssl/server.key
chmod 644 /opt/proxmox-redfish/config/ssl/server.crt
```

### Let's Encrypt Certificate (Production)

```bash
# Install certbot
apt install -y certbot

# Generate certificate
certbot certonly --standalone -d your-domain.com

# Copy certificates
cp /etc/letsencrypt/live/your-domain.com/fullchain.pem /opt/proxmox-redfish/config/ssl/server.crt
cp /etc/letsencrypt/live/your-domain.com/privkey.pem /opt/proxmox-redfish/config/ssl/server.key
cp /etc/letsencrypt/live/your-domain.com/chain.pem /opt/proxmox-redfish/config/ssl/ca.crt

# Set permissions
chown -R root:root /opt/proxmox-redfish/config/ssl/
chmod 600 /opt/proxmox-redfish/config/ssl/server.key
chmod 644 /opt/proxmox-redfish/config/ssl/server.crt
chmod 644 /opt/proxmox-redfish/config/ssl/ca.crt

# Setup automatic renewal
cat > /etc/cron.d/proxmox-redfish-ssl-renewal << 'EOF'
0 12 * * * /usr/bin/certbot renew --quiet && \
  cp /etc/letsencrypt/live/your-domain.com/fullchain.pem /opt/proxmox-redfish/config/ssl/server.crt && \
  cp /etc/letsencrypt/live/your-domain.com/privkey.pem /opt/proxmox-redfish/config/ssl/server.key && \
  cp /etc/letsencrypt/live/your-domain.com/chain.pem /opt/proxmox-redfish/config/ssl/ca.crt && \
  systemctl reload proxmox-redfish
EOF
```

### Custom Certificate Authority

```bash
# Generate private key
openssl genrsa -out /opt/proxmox-redfish/config/ssl/server.key 2048

# Generate certificate signing request
openssl req -new -key /opt/proxmox-redfish/config/ssl/server.key \
  -out /opt/proxmox-redfish/config/ssl/server.csr \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=$(hostname)"

# Submit CSR to your CA and receive server.crt
# Place CA certificate bundle in ca.crt

# Set permissions
chmod 600 /opt/proxmox-redfish/config/ssl/server.key
chmod 644 /opt/proxmox-redfish/config/ssl/server.crt
chmod 644 /opt/proxmox-redfish/config/ssl/ca.crt
```

## User Management

### Creating Dedicated Users

#### Option 1: Proxmox PAM User

In Proxmox web interface:
1. Go to **Datacenter** -> **Users**
2. Click **Add** -> **User**
3. Create the user (i.e. `redfish@pam`)
4. Set a strong password
5. Assign appropriate roles for each of the VMs that user should have access to

#### Option 2: API Token User

Create a dedicated user for API access
In Proxmox web interface:
1. Go to **Datacenter** -> **Users**
2. Click **Add** -> **User**
3. Create a user (i.e. `redfish@pam`)
4. Go to the user's API Tokens tab
5. Generate a new token with appropriate privileges

### Least Privilege Setup

If you wish to create a user with minimal required permissions, you can use the following steps:

In Proxmox web interface:
1. Create a user: (i.e. `redfish-limited@pam`)
2. Assign the following roles:
   - `VM.Audit` (read-only access to VM information)
   - `VM.PowerMgmt` (power management operations)
   - `VM.Config.CDROM` (virtual media operations)
   - `Datastore.AllocateSpace` (for ISO downloads)

3. Limit access to specific VMs if needed:
   - Right-click on **VM** -> **Permissions**
   - Add user with specific roles for that VM only

### Authentication Details

The intent for this project, in regards to user authentication, is to allow Proxmox roles and permissions to work as normal. This means that a user (i.e. `user@pve`) could be assigned an API token, and that token could be used to manage the VMs that they are configured to manage via existing roles and permissions that are configured in Proxmox.

The way that user is verified is with am account that has the correct permissions to look up access on behalf of the datacenter/pve host. This is configured in the `params.env` file (i.e. `root@pam` with a valid token). This account is used to look up the permissions of other users, and then uses the _user's_ permissions to perform the task. This is an important details, so that administrators are not confused about what account role performs which task.

This project is still very new, so things can change over time, but this is how it's intended to work right now.

1. Update configuration to use API token
   ```bash
   cat > /opt/proxmox-redfish/config/params.env << 'EOF'
   # Proxmox Configuration with API Token
   export PROXMOX_HOST="192.168.1.100"
   export PROXMOX_USER="redfish-api@pam"
   export PROXMOX_PASSWORD="your-api-token-here"
   export PROXMOX_NODE="pve"
   export PROXMOX_ISO_STORAGE="local"
   export VERIFY_SSL="false"

   # Other configuration...
   EOF
   ```

#### Non-Root Service Account (Advanced)

For enhanced security, run the service as a non-root user:

1. Create dedicated user
   ```bash
   useradd -r -s /bin/false -d /opt/proxmox-redfish proxmox-redfish
   ```

2. Set ownership
   ```bash
   chown -R proxmox-redfish:proxmox-redfish /opt/proxmox-redfish
   ```

3. Update service file
   ```bash
   sed -i 's/User=root/User=proxmox-redfish/' /etc/systemd/system/proxmox-redfish.service
   sed -i 's/Group=root/Group=proxmox-redfish/' /etc/systemd/system/proxmox-redfish.service

   # Reload and restart
   systemctl daemon-reload
   systemctl restart proxmox-redfish
   ```

## Monitoring and Logging

### Log Configuration

1. Configure log rotation
   ```bash
   cat > /etc/logrotate.d/proxmox-redfish << 'EOF'
   /var/log/proxmox-redfish/*.log {
       daily
       missingok
       rotate 7
       compress
       delaycompress
       notifempty
       create 644 root root
       postrotate
           systemctl reload proxmox-redfish
       endscript
   }
   EOF
   ```

### Health Checks

1. Create health check script
   ```bash

   cat > /opt/proxmox-redfish/health-check.sh << 'EOF'
   #!/bin/bash

   # Check if service is running
   if ! systemctl is-active --quiet proxmox-redfish; then
       echo "ERROR: Proxmox Redfish service is not running"
       exit 1
   fi

   # Check if API is responding
   if ! curl -k -s -o /dev/null -w "%{http_code}" https://localhost:8443/redfish/v1/ | grep -q "200"; then
       echo "ERROR: Redfish API is not responding"
       exit 1
   fi

   echo "OK: Proxmox Redfish daemon is healthy"
   exit 0
   EOF

   chmod +x /opt/proxmox-redfish/health-check.sh
   ```

2. Add to crontab for regular health checks
   ```bash
   echo "*/5 * * * * /opt/proxmox-redfish/health-check.sh" | crontab -
   ```

### Metrics Collection

1. Install monitoring tools
   ```bash
   apt install -y prometheus-node-exporter
   ```

2. Create custom metrics script
   ```bash
   cat > /opt/proxmox-redfish/metrics.sh << 'EOF'
   #!/bin/bash

   # Get service status
   SERVICE_STATUS=$(systemctl is-active proxmox-redfish)
   if [ "$SERVICE_STATUS" = "active" ]; then
       echo "proxmox_redfish_service_status 1"
   else
       echo "proxmox_redfish_service_status 0"
   fi
   ```

3. Get API response time
   ```bash
   RESPONSE_TIME=$(curl -k -s -w "%{time_total}" -o /dev/null https://localhost:8443/redfish/v1/)
   echo "proxmox_redfish_api_response_time $RESPONSE_TIME"
   ```

4. Get uptime
   ```bash
   UPTIME=$(systemctl show proxmox-redfish --property=ActiveEnterTimestamp | cut -d= -f2)
   echo "proxmox_redfish_uptime_seconds $(date -d "$UPTIME" +%s)"
   EOF

   chmod +x /opt/proxmox-redfish/metrics.sh
   ```

## Troubleshooting

### Common Issues and Solutions

#### Service Won't Start

1. Check service status
   ```bash
   systemctl status proxmox-redfish
   ```

2. View detailed logs
   ```bash
   journalctl -u proxmox-redfish -n 100
   ```

3. Check configuration
   ```bash
   source /opt/proxmox-redfish/config/params.env
   echo "PROXMOX_HOST: $PROXMOX_HOST"
   echo "PROXMOX_USER: $PROXMOX_USER"
   echo "SSL_CERT_FILE: $SSL_CERT_FILE"
   ```

4. Test Proxmox connectivity
   ```bash
   curl -k -u "$PROXMOX_USER:$PROXMOX_PASSWORD" "https://$PROXMOX_HOST:8006/api2/json/version"
   ```

#### SSL Certificate Issues

1. Check certificate validity
   ```bash
   openssl x509 -in /opt/proxmox-redfish/config/ssl/server.crt -text -noout
   ```

2. Check certificate and key match
   ```
   openssl x509 -noout -modulus -in /opt/proxmox-redfish/config/ssl/server.crt | openssl md5
   openssl rsa -noout -modulus -in /opt/proxmox-redfish/config/ssl/server.key | openssl md5
   ```

3. Regenerate certificate if needed
   ```
   cd /opt/proxmox-redfish
   openssl req -x509 -newkey rsa:4096 \
     -keyout config/ssl/server.key \
     -out config/ssl/server.crt \
     -days 365 -nodes \
     -subj "/CN=$(hostname)"
   chmod 600 config/ssl/server.key
   chmod 644 config/ssl/server.crt
   systemctl restart proxmox-redfish
   ```

#### Authentication Errors

1. Test Proxmox credentials
   ```bash
   curl -k -u "your-user@pam:your-password" \
     "https://your-proxmox-host:8006/api2/json/version"
   ```

2. Check user permissions

3. In Proxmox web interface, verify the user has appropriate roles

4. Test API token
   ```bash
   curl -k -H "Authorization: PVEAPIToken=your-token" \
     "https://your-proxmox-host:8006/api2/json/version"
   ```

#### Virtual Media Issues

1. Check ISO storage configuration
   ```bash
   pvesm status
   ```

2. Verify ISO storage permissions
   ```bash
   ls -la /var/lib/vz/template/iso/
   ```

3. Check available ISOs
   ```bash
   pvesm list local:iso
   ```

4. Test ISO download manually
   ```bash
   wget -O /tmp/test.iso "https://example.com/test.iso"
   ```

#### Network Connectivity Issues

1. Test network connectivity
   ```bash
   ping your-proxmox-host
   ```

2. Test port accessibility
   ```bash
   telnet your-proxmox-host 8006
   telnet your-proxmox-host 8443
   ```

3. Check firewall rules
   ```
   iptables -L -n | grep -E "(8006|8443)"
   ```

4. Test DNS resolution
   ```bash
   nslookup your-proxmox-host
   ```

### Debug Mode

Enable debug logging for troubleshooting:

1. Update configuration for debug mode
   ```bash
   sed -i 's/REDFISH_LOG_LEVEL="INFO"/REDFISH_LOG_LEVEL="DEBUG"/' \
     /opt/proxmox-redfish/config/params.env
   ```

2. Restart service
   ```bash
   systemctl restart proxmox-redfish
   ```

3. Monitor debug logs
   ```bash
   journalctl -u proxmox-redfish -f
   ```

### Performance Issues

1. Check resource usage
   ```bash
   top -p $(pgrep -f proxmox_redfish)
   ```

2. Check memory usage
   ```bash
   ps aux | grep proxmox_redfish
   ```

3. Monitor network connections
   ```bash
   netstat -tulpn | grep 8443
   ```

4. Check disk I/O
   ```bash
   iotop -p $(pgrep -f proxmox_redfish)
   ```

## Security Best Practices

1. **Use Dedicated Users**
   - Create dedicated users for Redfish operations
   - Use API tokens instead of passwords
   - Implement least privilege access

2. **Secure SSL Configuration**
   - Use proper SSL certificates in production
   - Regularly renew Let's Encrypt certificates
   - Implement certificate monitoring

3. Network Security
   - Configure firewall rules
      ```bash
      ufw allow 8443/tcp
      ufw deny 8443/tcp from 192.168.1.0/24  # Restrict access if needed
      ```
   - Use reverse proxy for additional security
   - Configure nginx or Apache as reverse proxy


4. File Permissions
   - Secure configuration files
     ```bash
     chmod 600 /opt/proxmox-redfish/config/params.env
     chmod 600 /opt/proxmox-redfish/config/ssl/server.key
     chmod 644 /opt/proxmox-redfish/config/ssl/server.crt
     ```
   - Secure service files
     ```bash
     chmod 644 /etc/systemd/system/proxmox-redfish.service
     ```

5. Regular Updates
   - Update the daemon regularly
     ```bash
     cd /opt/proxmox-redfish
     git pull origin main
     source venv/bin/activate
     pip install -e .
     systemctl restart proxmox-redfish
     ```

   - Update system packages
     ```bash
     apt update && apt upgrade -y
     ```

## Maintenance Checklist

### Daily Tasks
- `[ ]` Check service status: `systemctl status proxmox-redfish`
- `[ ]` Review logs: `journalctl -u proxmox-redfish --since "1 day ago"`
- `[ ]` Verify API accessibility: `curl -k https://localhost:8443/redfish/v1/`

### Weekly Tasks
- `[ ]` Check SSL certificate expiration
- `[ ]` Review user access and permissions
- `[ ]` Monitor resource usage
- `[ ]` Backup configuration files

### Monthly Tasks
- `[ ]` Update the daemon to latest version
- `[ ]` Review and rotate logs
- `[ ]` Test disaster recovery procedures
- `[ ]` Review security configurations

### Quarterly Tasks
- `[ ]` Perform security audit
- `[ ]` Update SSL certificates
- `[ ]` Review and update documentation
- `[ ]` Test backup and restore procedures

## Additional Resources
- [Proxmox VE Documentation](https://pve.proxmox.com/wiki/Main_Page)
- [Redfish Specification](https://www.dmtf.org/standards/redfish)
- [Systemd Service Documentation](https://www.freedesktop.org/software/systemd/man/systemd.service.html)
- [Let's Encrypt Documentation](https://letsencrypt.org/docs/) 