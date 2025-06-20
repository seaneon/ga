#!/bin/bash
# setup-tailwind.sh — Install Tailwind CLI binary for Go projects
set -e

# === CONFIGURATION ===
INSTALL_DIR="$HOME/.local/bin"
BINARY_NAME="tailwindcss"
TAILWIND_URL="https://github.com/tailwindlabs/tailwindcss/releases/latest/download/tailwindcss-linux-x64"
PROFILE_FILE="$HOME/.profile"

# Path entry to add to ~/.profile
PATH_ENTRY='export PATH="$HOME/.local/bin:$PATH"'

# === CREATE INSTALL DIR ===
echo "✅ Creating local bin directory (if missing): $INSTALL_DIR"
if ! mkdir -p "$INSTALL_DIR"; then
  echo "🔴 Failed to create local bin directory."
  exit 1
fi

# === DOWNLOAD CLI BINARY ===
echo ✅ Downloading Tailwind CLI...
if ! curl -sSL "$TAILWIND_URL" -o "$INSTALL_DIR/$BINARY_NAME"; then
  echo "🔴 Failed to download Tailwind CLI."
  exit 1
fi

# === MAKE IT EXECUTABLE ===
echo ✅ Making Tailwind binary executable...
if ! chmod +x "$INSTALL_DIR/$BINARY_NAME"; then
  echo "🔴 Failed to make Tailwind binary executable."
  exit 1
fi

# === CHECK AND UPDATE PATH ===
echo ✅ Checking if $INSTALL_DIR is configured in $PROFILE_FILE...
# Check for any line in ~/.profile that adds $HOME/.local/bin to PATH
if ! grep -E 'PATH=.*\$HOME/\.local/bin' "$PROFILE_FILE" > /dev/null 2>&1; then
  echo "🟢 Adding $INSTALL_DIR to your PATH in $PROFILE_FILE..."
  cat << EOF >> "$PROFILE_FILE"
$PATH_ENTRY
EOF
  echo "🡆 Added PATH entry. Run 'source $PROFILE_FILE' or restart your shell to apply."
else
  echo "🟢 PATH entry for $INSTALL_DIR already exists in $PROFILE_FILE."
fi

# Source ~/.profile to update PATH in the current session
if [ -f "$PROFILE_FILE" ]; then
  source "$PROFILE_FILE"
  echo "🟢 Sourced $PROFILE_FILE to update PATH in this session."
else
  echo "🟡 Warning: $PROFILE_FILE not found. PATH may not be updated in this session."
fi

# === VERIFY INSTALLATION ===
echo ✅ Verifying Tailwind CLI installation...
if command -v "$BINARY_NAME" > /dev/null; then
  "$BINARY_NAME" --help | head -n 5
  echo "✅ ✅ Tailwind CLI installed successfully!"
  echo "🡆 Example usage:"
  echo "$BINARY_NAME -i static/css/tailwind.css -o static/css/output.css --watch"
else
  echo "🔴 Error: Tailwind CLI not found in PATH."
  echo "🡆 Ensure 'source $PROFILE_FILE' has been run or restart your shell."
  exit 1
fi
