#!/bin/bash

# Proxmox-Redfish Daemon SSL Setup Script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_warning "This script should not be run as root for certificate generation"
        print_status "Continuing anyway..."
    fi
}

# Function to generate self-signed certificate
generate_self_signed() {
    print_status "Generating self-signed certificate..."
    
    # Get hostname
    HOSTNAME=$(hostname)
    DOMAIN=${1:-$HOSTNAME}
    
    print_status "Using domain: $DOMAIN"
    
    # Generate private key
    print_status "Generating private key..."
    openssl genrsa -out config/ssl/server.key 2048
    
    # Generate self-signed certificate
    print_status "Generating self-signed certificate..."
    openssl req -new -x509 -key config/ssl/server.key -out config/ssl/server.crt -days 365 \
        -subj "/C=US/ST=State/L=City/O=Proxmox-Redfish/CN=$DOMAIN"
    
    # Set proper permissions
    chmod 600 config/ssl/server.key
    chmod 644 config/ssl/server.crt
    
    print_success "Self-signed certificate generated successfully"
}

# Function to setup Let's Encrypt
setup_letsencrypt() {
    print_status "Setting up Let's Encrypt certificate..."
    
    DOMAIN=${1}
    if [ -z "$DOMAIN" ]; then
        print_error "Domain name required for Let's Encrypt"
        echo "Usage: $0 letsencrypt <domain>"
        exit 1
    fi
    
    print_status "Using domain: $DOMAIN"
    
    # Check if certbot is installed
    if ! command -v certbot &> /dev/null; then
        print_status "Installing certbot..."
        sudo apt update
        sudo apt install -y certbot
    fi
    
    # Generate certificate
    print_status "Generating Let's Encrypt certificate..."
    sudo certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos --email admin@$DOMAIN
    
    # Copy certificates
    print_status "Copying certificates to config/ssl/..."
    sudo cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" config/ssl/server.crt
    sudo cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" config/ssl/server.key
    sudo cp "/etc/letsencrypt/live/$DOMAIN/chain.pem" config/ssl/ca.crt
    
    # Set proper permissions
    sudo chown $USER:$USER config/ssl/server.crt config/ssl/server.key config/ssl/ca.crt
    chmod 600 config/ssl/server.key
    chmod 644 config/ssl/server.crt config/ssl/ca.crt
    
    print_success "Let's Encrypt certificate setup completed"
    
    # Setup renewal
    print_status "Setting up certificate renewal..."
    echo "0 12 * * * /usr/bin/certbot renew --quiet && sudo cp /etc/letsencrypt/live/$DOMAIN/fullchain.pem /opt/redfish_daemon/config/ssl/server.crt && sudo cp /etc/letsencrypt/live/$DOMAIN/privkey.pem /opt/redfish_daemon/config/ssl/server.key && sudo cp /etc/letsencrypt/live/$DOMAIN/chain.pem /opt/redfish_daemon/config/ssl/ca.crt && sudo chown $USER:$USER /opt/redfish_daemon/config/ssl/* && chmod 600 /opt/redfish_daemon/config/ssl/server.key && chmod 644 /opt/redfish_daemon/config/ssl/server.crt /opt/redfish_daemon/config/ssl/ca.crt" | sudo crontab -
    
    print_success "Certificate renewal scheduled"
}

# Function to test SSL configuration
test_ssl() {
    print_status "Testing SSL configuration..."
    
    # Check if certificate files exist
    if [ ! -f "config/ssl/server.crt" ]; then
        print_error "Certificate file not found: config/ssl/server.crt"
        return 1
    fi
    
    if [ ! -f "config/ssl/server.key" ]; then
        print_error "Private key file not found: config/ssl/server.key"
        return 1
    fi
    
    # Test certificate validity
    print_status "Testing certificate validity..."
    if openssl x509 -in config/ssl/server.crt -text -noout > /dev/null 2>&1; then
        print_success "Certificate is valid"
    else
        print_error "Certificate is invalid"
        return 1
    fi
    
    # Test private key
    print_status "Testing private key..."
    if openssl rsa -in config/ssl/server.key -check > /dev/null 2>&1; then
        print_success "Private key is valid"
    else
        print_error "Private key is invalid"
        return 1
    fi
    
    # Test certificate and key match
    print_status "Testing certificate and key match..."
    CERT_MODULUS=$(openssl x509 -noout -modulus -in config/ssl/server.crt | openssl md5)
    KEY_MODULUS=$(openssl rsa -noout -modulus -in config/ssl/server.key | openssl md5)
    
    if [ "$CERT_MODULUS" = "$KEY_MODULUS" ]; then
        print_success "Certificate and private key match"
    else
        print_error "Certificate and private key do not match"
        return 1
    fi
    
    # Test CA bundle if it exists
    if [ -f "config/ssl/ca.crt" ]; then
        print_status "Testing CA bundle..."
        if openssl verify -CAfile config/ssl/ca.crt config/ssl/server.crt > /dev/null 2>&1; then
            print_success "CA bundle is valid"
        else
            print_warning "CA bundle validation failed (this may be normal for self-signed certificates)"
        fi
    fi
    
    print_success "SSL configuration test completed successfully"
}

# Function to show current SSL status
show_status() {
    print_status "Current SSL configuration status:"
    echo
    
    if [ -f "config/ssl/server.crt" ]; then
        print_success "✓ Certificate file exists"
        echo "  Certificate: $(openssl x509 -in config/ssl/server.crt -noout -subject | cut -d'=' -f3-)"
        echo "  Expires: $(openssl x509 -in config/ssl/server.crt -noout -enddate | cut -d'=' -f2-)"
    else
        print_error "✗ Certificate file missing"
    fi
    
    if [ -f "config/ssl/server.key" ]; then
        print_success "✓ Private key file exists"
        echo "  Permissions: $(ls -la config/ssl/server.key | awk '{print $1}')"
    else
        print_error "✗ Private key file missing"
    fi
    
    if [ -f "config/ssl/ca.crt" ]; then
        print_success "✓ CA bundle exists"
    else
        print_warning "⚠ CA bundle not found (optional)"
    fi
    
    echo
    print_status "Environment variables:"
    echo "  SSL_CERT_FILE: ${SSL_CERT_FILE:-/opt/redfish_daemon/config/ssl/server.crt}"
    echo "  SSL_KEY_FILE: ${SSL_KEY_FILE:-/opt/redfish_daemon/config/ssl/server.key}"
    echo "  SSL_CA_FILE: ${SSL_CA_FILE:-/opt/redfish_daemon/config/ssl/ca.crt}"
}

# Main function
main() {
    echo "Proxmox-Redfish Daemon SSL Setup"
    echo "================================"
    echo
    
    # Create SSL directory if it doesn't exist
    mkdir -p config/ssl
    
    case "${1:-help}" in
        "self-signed")
            check_root
            generate_self_signed "$2"
            ;;
        "letsencrypt")
            check_root
            setup_letsencrypt "$2"
            ;;
        "test")
            test_ssl
            ;;
        "status")
            show_status
            ;;
        "help"|"-h"|"--help")
            echo "Usage: $0 [command] [options]"
            echo
            echo "Commands:"
            echo "  self-signed [domain]  - Generate self-signed certificate"
            echo "  letsencrypt <domain>  - Setup Let's Encrypt certificate"
            echo "  test                  - Test SSL configuration"
            echo "  status                - Show current SSL status"
            echo "  help                  - Show this help message"
            echo
            echo "Examples:"
            echo "  $0 self-signed"
            echo "  $0 self-signed myhost.example.com"
            echo "  $0 letsencrypt myhost.example.com"
            echo "  $0 test"
            echo "  $0 status"
            exit 0
            ;;
        *)
            print_error "Unknown command: $1"
            echo "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
    
    echo
    print_success "SSL setup completed successfully!"
}

# Run main function
main "$@" 