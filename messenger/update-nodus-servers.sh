#!/bin/bash
# Update DNA Nodus on all production servers
# Runs nodus_build.sh on each server sequentially

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SERVERS=(
    "154.38.182.161:US-1"
    "164.68.105.227:EU-1"
    "164.68.116.180:EU-2"
)

echo -e "${GREEN}=== DNA Nodus Server Update ===${NC}"
echo ""

for entry in "${SERVERS[@]}"; do
    IP="${entry%%:*}"
    NAME="${entry##*:}"

    echo -e "${YELLOW}[$NAME] Updating $IP...${NC}"

    if ssh root@$IP "cd /opt/dna-messenger && bash nodus_build.sh"; then
        echo -e "${GREEN}[$NAME] Success${NC}"
    else
        echo -e "${RED}[$NAME] Failed${NC}"
    fi

    echo ""
done

echo -e "${GREEN}=== Update Complete ===${NC}"
