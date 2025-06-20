#!/bin/bash

set -e

GO_VERSION="1.24.2"
ARCH="amd64"
OS="linux"
INSTALL_DIR="/usr/local"
PROFILE="$HOME/.bashrc"

# Download and install Go
echo "Downloading Go $GO_VERSION..."
wget -q "https://go.dev/dl/go${GO_VERSION}.${OS}-${ARCH}.tar.gz" -O /tmp/go.tar.gz

echo "Extracting Go to $INSTALL_DIR..."
sudo rm -rf ${INSTALL_DIR}/go
sudo tar -C ${INSTALL_DIR} -xzf /tmp/go.tar.gz

# Clean up
rm /tmp/go.tar.gz

# Setup environment variables
echo "Configuring environment variables..."
if ! grep -q 'export PATH=$PATH:/usr/local/go/bin' "$PROFILE"; then
    echo -e "\n# Go environment setup" >> "$PROFILE"
    echo 'export PATH=$PATH:/usr/local/go/bin' >> "$PROFILE"
    echo 'export GOPATH=$HOME/go' >> "$PROFILE"
    echo 'export PATH=$PATH:$GOPATH/bin' >> "$PROFILE"
fi

# Create Go workspace
mkdir -p "$HOME/go/bin" "$HOME/go/pkg" "$HOME/go/src"

echo "Go $GO_VERSION installation completed!"
echo "To activate it now, run:"
echo ""
echo "    source ~/.profile"
echo ""
sleep 2
echo "Then test with:"
echo "    go version"
