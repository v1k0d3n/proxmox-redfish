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
| `PROXMOX_NODE` | _(unset)_ | Restrict the daemon to one node. Unset means guests are found wherever they run (experimental). |
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

# Create configuration file. systemd reads this as an EnvironmentFile, which
# accepts plain NAME=value lines only -- an "export" prefix is rejected and
# the setting silently does not reach the daemon.
cat > /opt/proxmox-redfish/config/params.env << 'EOF'
# Proxmox Configuration
PROXMOX_HOST="192.168.1.100"
PROXMOX_NODE="pve"
PROXMOX_ISO_STORAGE="local"
VERIFY_SSL="false"

# Redfish Configuration
REDFISH_PORT="8443"
REDFISH_HOST="0.0.0.0"

# SSL Configuration
SSL_CERT_FILE="/opt/proxmox-redfish/config/ssl/server.crt"
SSL_KEY_FILE="/opt/proxmox-redfish/config/ssl/server.key"
SSL_CA_FILE="/opt/proxmox-redfish/config/ssl/ca.crt"

# Logging Configuration
REDFISH_LOG_LEVEL="INFO"
REDFISH_LOGGING_ENABLED="true"
EOF
```

### Command Line Options

Configuration comes from the environment. These options override it for the
few settings that are useful to change per invocation:

| Option | Overrides | Default |
|---|---|---|
| `--port` | `REDFISH_PORT` | `8443` |
| `--host` | `REDFISH_HOST` | every interface |
| `--log-level` | `REDFISH_LOG_LEVEL` | `INFO` |

Precedence is command line, then environment, then the default.

`--host` binds a single address. Restricting the daemon to a provisioning
interface is worth doing when the host is also reachable from a network that
has no business reaching it:

```bash
proxmox-redfish --port 8000 --host 10.0.0.5
```

TLS is used when both `SSL_CERT_FILE` and `SSL_KEY_FILE` are set. Setting
only one of them starts the daemon without TLS.

## ISO Storage

`PROXMOX_ISO_STORAGE` names the storage that `VirtualMedia.InsertMedia`
uploads to when it is given an image URL. It defaults to `local` because
that is the storage Proxmox creates by default, but any storage name is
accepted and nothing in the daemon treats `local` specially.

The storage must be file-backed, since an ISO is a file. Proxmox reports a
filesystem path for these types, and the daemon uses `<path>/template/iso`:

| Type | Usable | Notes |
|---|---|---|
| `dir` | yes | path is whatever the operator configured |
| `nfs`, `cifs` | yes | mounted at `/mnt/pve/<name>`, and can be shared between nodes |
| `cephfs`, `glusterfs` | yes | likewise |
| `zfspool`, `lvm`, `lvmthin`, `rbd`, `iscsi` | no | block storage, no filesystem path |

Configuring a block storage is rejected with an error naming its type, since
no ISO can be written there.

A storage with `shared: 1` is visible from every node in a cluster, so an
image uploaded once can be attached to a VM wherever it runs. A node-local
`dir` storage only serves VMs on that node.

The calling account needs `Datastore.AllocateTemplate` to upload, and
`Datastore.Audit` to see the storage at all. A storage the caller cannot see
is reported as not found — the storage list Proxmox returns is filtered by
the caller's permissions.


## Single Node and Clusters

The daemon addresses a guest by its VM id. Proxmox ids are unique across a
cluster, so an id identifies one guest wherever it runs, and the node it
runs on is looked up rather than configured.

### Single node

Set `PROXMOX_NODE` to the node's name. The daemon manages only the guests on
that node and ignores anything else. This is the default arrangement and the
one most deployments use.

```bash
PROXMOX_HOST=proxmox.example.com
PROXMOX_NODE=pve
```

### Cluster (experimental)

Leave `PROXMOX_NODE` unset. The daemon then finds each guest wherever it is
running, so a guest that migrates keeps working without a configuration
change, and every node's guests are reachable through one endpoint.

```bash
PROXMOX_HOST=proxmox.example.com
# PROXMOX_NODE deliberately unset
```

> **Experimental.** Cluster operation has been exercised against a single
> node and reviewed against the Proxmox API, but not yet run on a real
> multi-node cluster. If you use it, please report what you find --
> especially around migration and shared storage. Feedback is welcome on
> the issue tracker.

### Requirements for cluster operation

**A shared ISO storage.** `VirtualMedia.InsertMedia` uploads an image to the
node that will attach it. A node-local `dir` storage cannot serve a guest on
another node, so a guest that migrates would lose access to its image. Use a
storage that reports `shared: 1` -- NFS, CIFS or CephFS -- and set
`PROXMOX_ISO_STORAGE` to it. See "ISO Storage" above for which types work.

**Permissions on every node's guests.** Proxmox permissions are cluster-wide,
so a role granted at `/vms` applies everywhere. Granting per-VM works too, it
is simply more entries to maintain.

### Restricting which guests a caller manages

A caller only ever sees guests their Proxmox permissions allow, because the
listing the daemon uses is filtered by those permissions. That is the
supported way to limit scope, and it needs nothing from this daemon.

Pools are a convenient unit for it. A pool groups guests, and `/pool/<name>`
is a permission path, so one grant covers everything in the pool:

```bash
pveum pool add openshift
pveum pool modify openshift --vms 100,101,102
pveum acl modify /pool/openshift --users bmcadmin@pve --roles RedfishOperator
```

That account will then see exactly those guests in `/redfish/v1/Systems`, on
whichever nodes they run. Note that pool membership alone grants nothing --
the role has to be granted on the pool path.

A pool can contain storage as well, so the ISO storage can be granted in the
same place if you prefer to manage it that way.

### What an unknown id returns

A request for an id the caller cannot see returns 404. The listing is
filtered by permission, so a guest that does not exist and a guest the
caller may not see are indistinguishable to the daemon. Reporting both as
missing also avoids confirming that an id exists to someone with no rights
to it.

Container ids behave the same way. Containers share the id namespace with
virtual machines but are not managed through this daemon, so their ids are
reported as missing.


## Proxmox Permissions

The daemon connects to Proxmox as the account that made the Redfish
request. Proxmox evaluates its own ACLs on every call, so a Redfish user
can reach exactly the VMs they have been granted and nothing else.

There is no service account standing in for callers, and no permission
logic in this daemon. A caller with no Proxmox privileges can
authenticate and will then be refused everything, returning
`Base.1.0.InsufficientPrivilege` with the underlying Proxmox reason.

### Required privileges

| Privilege | Needed for |
|---|---|
| `VM.Audit` | Reading `Systems`, `Bios`, `Processors`, `Storage`, `EthernetInterfaces` |
| `VM.PowerMgmt` | `ComputerSystem.Reset` (On, ForceOff, GracefulShutdown, restarts) |
| `VM.Config.CDROM` | `VirtualMedia.InsertMedia` and `VirtualMedia.EjectMedia` |
| `VM.Config.Disk` | `BootSourceOverrideTarget` |
| `Datastore.AllocateTemplate` | Uploading an ISO supplied to `InsertMedia` as a URL |
| `Datastore.Audit` | Listing the ISO storage |

The first four apply to the VM path, the last two to the ISO storage path.

**The built-in `PVEVMUser` role is not enough.** It covers `VM.Audit`,
`VM.PowerMgmt` and `VM.Config.CDROM`, so reads, power operations and
virtual media all succeed and only boot override fails — which makes it
an easy mistake to ship. Boot order is a disk option in Proxmox
(`$diskoptions` in `PVE::API2::Qemu`), guarded by `VM.Config.Disk`, not
`VM.Config.Options`.

### Where to run these commands

On any node. Proxmox has no management node -- every node is equal, and
users, roles and ACLs live in `/etc/pve/user.cfg` on the cluster
filesystem, which replicates to every node in real time. Running `pveum`
on one node configures the whole cluster.

The node has to have quorum. Without it `/etc/pve` is read only and these
commands fail rather than half-apply.

### Setting up a Redfish account

**1. Create the role.** It carries the six privileges above, and nothing
else:

```bash
pveum role add RedfishOperator --privs \
  "VM.Audit,VM.PowerMgmt,VM.Config.CDROM,VM.Config.Disk,Datastore.AllocateTemplate,Datastore.Audit"
```

**2. Create the user.** The `@pve` realm is a Proxmox account and needs
nothing on the host. `@pam` delegates to a Linux user, so a `@pam` name
with no matching system account is accepted here and then fails to
authenticate:

```bash
pveum user add redfish@pve
pveum passwd redfish@pve
```

`pveum passwd` prompts. Passing `--password` to `user add` instead puts
the password in your shell history and in the process list while it runs.

**3. Grant the role.** Once per VM the account should manage, and once on
the storage that holds ISOs:

```bash
pveum acl modify /vms/101 --users redfish@pve --roles RedfishOperator
pveum acl modify /storage/local --users redfish@pve --roles RedfishOperator
```

`/vms/101` grants one VM; `/vms` grants all of them. The storage path
must name the storage the daemon is configured to use, its
`PROXMOX_ISO_STORAGE`. Power and boot work without it, and virtual media
fails partway through instead.

**4. Check what landed.** The list is the whole picture -- which paths,
which roles, which accounts:

```bash
pveum acl list
```

**5. Confirm the daemon agrees.** Ask it what the account can see:

```bash
curl -sk -u 'redfish@pve:<password>' \
  https://proxmox.example.com:8443/redfish/v1/Systems
```

`Members@odata.count` should equal the number of VMs granted, and no
more. Zero means the ACLs did not apply to this account. A 401 means the
credentials are wrong, which is a different problem.

In the web UI the same thing is *Datacenter → Permissions → Add → User
Permission*, once with a `/vms/...` path and once with a `/storage/...`
path. Roles are not path-specific, so one role serves both.

### Adding accounts later

The role is made once and reused. Another account needs only a user and
its own grants:

```bash
pveum user add redfish2@pve
pveum passwd redfish2@pve
pveum acl modify /vms/102 --users redfish2@pve --roles RedfishOperator
pveum acl modify /storage/local --users redfish2@pve --roles RedfishOperator
```

Several accounts can hold the same path, and one account can hold many
paths. To widen an existing account, grant it another path; to narrow it,
delete the grant you no longer want:

```bash
pveum acl delete /vms/101 --users redfish@pve --roles RedfishOperator
```

### Removing an account

Grants first, then the account, then the role once nothing uses it:

```bash
pveum acl delete /vms/101 --users redfish@pve --roles RedfishOperator
pveum acl delete /storage/local --users redfish@pve --roles RedfishOperator
pveum user delete redfish@pve
pveum role delete RedfishOperator
```

Deleting a user takes its API tokens with it. Its ACL entries do not go
on their own, so remove those first or `pveum acl list` keeps showing
them.

### API tokens

An API token works anywhere a password does, passed as Basic auth with
the token id in the username:

```bash
curl -k -u 'redfish@pve!bmc:<token-value>' \
  https://proxmox.example.com:8443/redfish/v1/Systems
```

Tokens suit automation: they are sent with each request and skip the
ticket exchange a password requires.

**A token does not inherit its user's privileges.** Tokens are created
with privilege separation on, which means the token holds only what has
been granted to the token itself -- nothing from the account that owns
it, even if that account is an administrator. The ACL goes on the token
identity:

```bash
pveum acl modify /vms/101 --tokens 'redfish@pve!bmc' --roles RedfishOperator
pveum acl modify /storage/local --tokens 'redfish@pve!bmc' --roles RedfishOperator
```

This is worth knowing before it happens to you, because of how it fails.
Authentication succeeds. Nothing returns 401. `Systems` comes back empty,
individual systems return 404, and the daemon looks like it cannot see
any guests -- which reads as a daemon fault rather than a missing grant.
If a token sees nothing, check `pveum acl list` for the token identity
before looking anywhere else.

A password account is the simpler choice for most people, because
privilege separation cannot quietly strip it.

### Upgrading from a release before caller identity

Earlier versions performed all Proxmox operations as `PROXMOX_USER`,
which meant any account that could authenticate could drive any VM.
Callers now need real privileges.

Before upgrading, grant every account that uses the Redfish API the
privileges above on the VMs it manages. Without them the daemon still
authenticates the caller and then returns 403 on every operation.

`PROXMOX_USER` and `PROXMOX_PASSWORD` are no longer used to service
requests.

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
   # Proxmox Configuration. Callers authenticate with their own account or
   # API token; the daemon holds no credentials.
   export PROXMOX_HOST="192.168.1.100"
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
   echo "PROXMOX_NODE: $PROXMOX_NODE"
   echo "SSL_CERT_FILE: $SSL_CERT_FILE"
   ```

4. Test Proxmox connectivity
   ```bash
   curl -k -u "<user>@pam:<password>" "https://$PROXMOX_HOST:8006/api2/json/version"
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