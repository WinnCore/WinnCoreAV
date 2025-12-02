#!/bin/bash
set -u

# --- COLORS FOR UI ---
GREEN='\033 Please paste your Gemini API Key (starts with AIza...):${NC}"
read -s -p "    Key: " GEMINI_KEY
echo ""

if]; then
    echo -e "${RED}[!] No key entered. Exiting.${NC}"
    exit 1
fi

# --- STEP 2: VERIFY KEY ---
echo -e "\n${BLUE}[*] Verifying key with Google servers...${NC}"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Content-Type: application/json" \
    -d '{ "contents": [{"parts":[{"text": "Hello"}]}] }' \
    "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${GEMINI_KEY}")

if]; then
    echo -e "${GREEN}[✓] SUCCESS: API Key is valid!${NC}"
else
    echo -e "${RED}[X] ERROR: API Key failed verification (HTTP $HTTP_CODE).${NC}"
    echo "    Please check your key and try again."
    exit 1
fi

# --- STEP 3: PERSIST KEY ---
SHELL_CONFIG=""
if]; then
    SHELL_CONFIG="$HOME/.zshrc"
else
    SHELL_CONFIG="$HOME/.bashrc"
fi

echo -e "\n${BLUE}[*] Saving key to ${SHELL_CONFIG}...${NC}"

# Remove old key if exists to prevent duplicates
sed -i '/export GEMINI_API_KEY=/d' "$SHELL_CONFIG"

# Append new key
echo "export GEMINI_API_KEY='$GEMINI_KEY'" >> "$SHELL_CONFIG"
echo -e "${GREEN}[✓] Key saved. It will auto-connect in future sessions.${NC}"

# Export for current session immediately
export GEMINI_API_KEY="$GEMINI_KEY"

# --- STEP 4: INSTALL CLI (Optional) ---
echo -e "\n${YELLOW}[?] Do you want to install the official 'gemini' CLI tool? (Requires Node.js)${NC}"
read -p "    Install gemini-cli? (y/n): " INSTALL_CHOICE

if$ ]]; then
    if command -v npm &> /dev/null; then
        echo -e "${BLUE}[*] Installing @google/gemini-cli...${NC}"
        # Try installing globally; use sudo if permission denied
        npm install -g @google/gemini-cli |

| sudo npm install -g @google/gemini-cli
        
        echo -e "${GREEN}[✓] Gemini CLI installed!${NC}"
        echo -e "    Try running: ${YELLOW}gemini \"Fix my python script\"${NC}"
    else
        echo -e "${RED}[!] Node.js/npm not found. Skipping CLI install.${NC}"
        echo "    (Your API Key is still saved for other tools though!)"
    fi
fi

echo -e "\n${GREEN}══════════════════ SETUP COMPLETE ══════════════════${NC}"
echo "To apply changes immediately to this window, run:"
echo -e "${YELLOW}source $SHELL_CONFIG${NC}"
