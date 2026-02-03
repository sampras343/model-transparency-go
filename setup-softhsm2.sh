#!/bin/bash
# Fixed SoftHSM2 Setup Script - uses user home directory for token storage

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== SoftHSM2 Setup Script ===${NC}\n"

# Step 1: Find SoftHSM2 module
echo -e "${YELLOW}Step 1: Locating SoftHSM2 module...${NC}"
MODULE_PATH=$(find /usr/lib* -name "libsofthsm2.so" 2>/dev/null | grep -v "softhsm/" | head -1)
if [ -z "$MODULE_PATH" ]; then
    echo -e "${RED}✗ Could not find libsofthsm2.so${NC}"
    echo "Please install SoftHSM2: sudo dnf install softhsm"
    exit 1
fi
echo -e "${GREEN}✓ Found module at: ${MODULE_PATH}${NC}"

# Step 2: Configure SoftHSM2 to use home directory
echo -e "\n${YELLOW}Step 2: Configuring SoftHSM2...${NC}"
SOFTHSM_DIR="$HOME/.config/softhsm2"
SOFTHSM_TOKENS="$SOFTHSM_DIR/tokens"
SOFTHSM_CONF="$SOFTHSM_DIR/softhsm2.conf"

mkdir -p "$SOFTHSM_TOKENS"
chmod 700 "$SOFTHSM_DIR"
chmod 700 "$SOFTHSM_TOKENS"

cat > "$SOFTHSM_CONF" <<EOF
# SoftHSM v2 configuration file
directories.tokendir = $SOFTHSM_TOKENS
objectstore.backend = file
log.level = INFO
EOF

export SOFTHSM2_CONF="$SOFTHSM_CONF"
echo -e "${GREEN}✓ Configuration created at: $SOFTHSM_CONF${NC}"
echo -e "${GREEN}✓ Token directory: $SOFTHSM_TOKENS${NC}"

# Step 3: Initialize token
echo -e "\n${YELLOW}Step 3: Initializing token 'mytoken'...${NC}"
TOKEN_PIN="1234"
SO_PIN="5678"

# Check if token already exists
if softhsm2-util --show-slots 2>/dev/null | grep -q "mytoken"; then
    echo -e "${GREEN}✓ Token 'mytoken' already exists${NC}"
else
    SOFTHSM2_CONF="$SOFTHSM_CONF" softhsm2-util --init-token --free --label "mytoken" --pin $TOKEN_PIN --so-pin $SO_PIN
    echo -e "${GREEN}✓ Token initialized${NC}"
fi

# Step 4: Show token slots
echo -e "\n${YELLOW}Step 4: Listing available slots...${NC}"
SOFTHSM2_CONF="$SOFTHSM_CONF" softhsm2-util --show-slots

# Step 5: Generate key pair
echo -e "\n${YELLOW}Step 5: Generating EC key pair...${NC}"
if SOFTHSM2_CONF="$SOFTHSM_CONF" pkcs11-tool --module "$MODULE_PATH" --login --pin $TOKEN_PIN --list-objects 2>/dev/null | grep -q "Private Key Object"; then
    echo -e "${GREEN}✓ Key pair already exists${NC}"
else
    SOFTHSM2_CONF="$SOFTHSM_CONF" pkcs11-tool --module "$MODULE_PATH" \
        --login --pin $TOKEN_PIN \
        --keypairgen --key-type EC:secp256r1 \
        --label mykey \
        --id 01
    echo -e "${GREEN}✓ Key pair generated${NC}"
fi

# Step 6: Verify setup
echo -e "\n${YELLOW}Step 6: Verifying setup...${NC}"
echo -e "${GREEN}Token and key objects:${NC}"
SOFTHSM2_CONF="$SOFTHSM_CONF" pkcs11-tool --module "$MODULE_PATH" --login --pin $TOKEN_PIN --list-objects | head -20

# Step 7: Create configuration file
echo -e "\n${GREEN}=== Setup Complete! ===${NC}\n"

cat > softhsm2-config.sh <<EOF
#!/bin/bash
# SoftHSM2 Configuration
export SOFTHSM2_CONF="$SOFTHSM_CONF"
export SOFTHSM2_MODULE_PATH="$MODULE_PATH"
export SOFTHSM2_TOKEN_LABEL="mytoken"
export SOFTHSM2_KEY_LABEL="mykey"
export SOFTHSM2_PIN="1234"
export SOFTHSM2_URI="pkcs11:token=mytoken;object=mykey?module-path=${MODULE_PATH}&pin-value=1234"

echo "✓ SoftHSM2 configuration loaded!"
echo "  Module: \$SOFTHSM2_MODULE_PATH"
echo "  Config: \$SOFTHSM2_CONF"
echo "  Token:  \$SOFTHSM2_TOKEN_LABEL"
echo "  Key:    \$SOFTHSM2_KEY_LABEL"
echo ""
echo "Sign a model with PKCS#11:"
echo "  SOFTHSM2_CONF=\"\$SOFTHSM2_CONF\" ./build/model-signing sign pkcs11 MODEL_PATH \\"
echo "    --pkcs11-uri \"\$SOFTHSM2_URI\" \\"
echo "    --signature SIGNATURE_PATH"
echo ""
echo "Example:"
echo "  SOFTHSM2_CONF=\"\$SOFTHSM2_CONF\" ./build/model-signing sign pkcs11 test-model \\"
echo "    --pkcs11-uri \"\$SOFTHSM2_URI\" \\"
echo "    --signature test-model-pkcs11.sig"
EOF

chmod +x softhsm2-config.sh

echo -e "${YELLOW}Configuration saved to: softhsm2-config.sh${NC}\n"
echo -e "${GREEN}To sign a model:${NC}\n"
echo -e "${YELLOW}SOFTHSM2_CONF=\"$SOFTHSM_CONF\" ./build/model-signing sign pkcs11 test-model \\${NC}"
echo -e "${YELLOW}  --pkcs11-uri \"pkcs11:token=mytoken;object=mykey?module-path=${MODULE_PATH}&pin-value=1234\" \\${NC}"
echo -e "${YELLOW}  --signature test-model-pkcs11.sig${NC}"
echo -e ""
echo -e "${GREEN}Or load the config for easier reuse:${NC}"
echo -e "  ${YELLOW}source softhsm2-config.sh${NC}"
echo -e ""
echo -e "  ${YELLOW}SOFTHSM2_CONF=\"\$SOFTHSM2_CONF\" ./build/model-signing sign pkcs11 test-model \\${NC}"
echo -e "  ${YELLOW}  --pkcs11-uri \"\$SOFTHSM2_URI\" \\${NC}"
echo -e "  ${YELLOW}  --signature test-model-pkcs11.sig${NC}"
