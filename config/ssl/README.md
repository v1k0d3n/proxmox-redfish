# SSL Certificate Directory

This directory is for SSL certificates and private keys used by the Proxmox-Redfish daemon.

## Certificate Generation

### Option 1: Self-Signed Certificate (Development/Testing)

Generate a self-signed certificate for development or testing:

```bash
# Generate private key
openssl genrsa -out server.key 2048

# Generate self-signed certificate
openssl req -new -x509 -key server.key -out server.crt -days 365 \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=your-hostname.com"

# Set proper permissions
chmod 600 server.key
chmod 644 server.crt
```

### Option 2: Certificate with CA (Production)

For production use with a Certificate Authority:

```bash
# Generate private key
openssl genrsa -out server.key 2048

# Generate certificate signing request (CSR)
openssl req -new -key server.key -out server.csr \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=your-hostname.com"

# Submit CSR to your CA and receive server.crt
# Place the CA certificate bundle in ca.crt
```

### Option 3: Let's Encrypt (Recommended for Production)

For automatic certificate management:

```bash
# Install certbot
sudo apt install certbot

# Generate certificate
sudo certbot certonly --standalone -d your-hostname.com

# Copy certificates to this directory
sudo cp /etc/letsencrypt/live/your-hostname.com/fullchain.pem server.crt
sudo cp /etc/letsencrypt/live/your-hostname.com/privkey.pem server.key
sudo cp /etc/letsencrypt/live/your-hostname.com/chain.pem ca.crt

# Set proper permissions
sudo chown $USER:$USER server.crt server.key ca.crt
chmod 600 server.key
chmod 644 server.crt ca.crt
```

## File Structure

Place your SSL certificate files here:

- `server.crt` - SSL certificate file (required)
- `server.key` - Private key file (required)
- `ca.crt` - Certificate Authority bundle (optional)

## Security Notes

- **Private Key Security**: Ensure proper file permissions: `chmod 600 server.key`
- **Version Control**: Keep private keys secure and never commit them to version control
- **File Permissions**: The `.gitignore` file excludes `*.key` and `*.crt` files from version control
- **Certificate Renewal**: For Let's Encrypt, set up automatic renewal

## Configuration

The daemon automatically uses these default paths:

```bash
# Default SSL certificate paths (can be overridden with environment variables)
SSL_CERT_FILE=/opt/redfish_daemon/config/ssl/server.crt
SSL_KEY_FILE=/opt/redfish_daemon/config/ssl/server.key
SSL_CA_FILE=/opt/redfish_daemon/config/ssl/ca.crt  # Optional
```

### Environment Variable Override

You can override the default paths with environment variables:

```bash
# In config/params.env or systemd service file
export SSL_CERT_FILE=/path/to/your/certificate.crt
export SSL_KEY_FILE=/path/to/your/private.key
export SSL_CA_FILE=/path/to/your/ca-bundle.crt  # Optional
```

## Testing SSL Configuration

To test your SSL configuration:

```bash
# Test certificate validity
openssl x509 -in server.crt -text -noout

# Test private key
openssl rsa -in server.key -check

# Test certificate chain (if using CA)
openssl verify -CAfile ca.crt server.crt
```

## Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure proper file permissions
   ```bash
   chmod 600 server.key
   chmod 644 server.crt
   ```

2. **Certificate Not Found**: Check file paths and names
   ```bash
   ls -la config/ssl/
   ```

3. **SSL Context Error**: Verify certificate and key match
   ```bash
   openssl x509 -noout -modulus -in server.crt | openssl md5
   openssl rsa -noout -modulus -in server.key | openssl md5
   ```

4. **CA Bundle Issues**: Ensure CA certificate is in PEM format
   ```bash
   openssl x509 -in ca.crt -text -noout
   ``` 