#!/bin/bash
# keygate global installer
# Usage: curl -sSL https://raw.githubusercontent.com/feelgom/keygate/master/install-global.sh | bash
set -e

REPO="https://github.com/feelgom/keygate.git"
INSTALL_DIR="$HOME/.keygate-install"

echo "Installing keygate..."

# Method 1: pipx (preferred)
if command -v pipx &>/dev/null; then
    pipx install "git+$REPO" 2>/dev/null || pipx upgrade keygate 2>/dev/null || pipx install --force "git+$REPO"
    echo ""
    echo "✓ Installed via pipx. Run: kg --version"
    exit 0
fi

# Method 2: pip with --user
if command -v pip3 &>/dev/null; then
    pip3 install --user "git+$REPO" 2>/dev/null && {
        echo ""
        echo "✓ Installed via pip3 --user."
        echo "  Make sure ~/.local/bin is in your PATH."
        echo "  Run: kg --version"
        exit 0
    }
fi

# Method 3: venv fallback
echo "No pipx or pip3 found. Installing to $INSTALL_DIR..."
rm -rf "$INSTALL_DIR"
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install "git+$REPO"

# Symlink to ~/bin
mkdir -p "$HOME/bin"
ln -sf "$INSTALL_DIR/venv/bin/kg" "$HOME/bin/kg"
ln -sf "$INSTALL_DIR/venv/bin/keygate" "$HOME/bin/keygate"

echo ""
echo "✓ Installed to $INSTALL_DIR"
echo "  Symlinked: ~/bin/kg"
if ! echo "$PATH" | tr ':' '\n' | grep -q "$HOME/bin"; then
    echo "  ⚠ Add ~/bin to PATH: export PATH=\"\$HOME/bin:\$PATH\""
fi
echo "  Run: kg --version"
