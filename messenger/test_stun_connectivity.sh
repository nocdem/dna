#!/bin/bash
#
# STUN Connectivity Diagnostic Tool
# Tests network connectivity to STUN servers used by DNA Messenger
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE} DNA Messenger - STUN Connectivity Test${NC}"
echo -e "${BLUE}=========================================${NC}"
echo ""

# STUN servers to test (same order as DNA Messenger - verified working)
STUN_SERVERS=(
    "stun.cloudflare.com:3478"
    "stun.l.google.com:19302"
    "stun1.l.google.com:19302"
)

# 1. Check basic network connectivity
echo -e "${YELLOW}[1/5] Checking basic network connectivity...${NC}"
if ping -c 1 -W 2 8.8.8.8 > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} Internet connection: OK"
else
    echo -e "${RED}✗${NC} Internet connection: FAILED"
    echo -e "${YELLOW}Cannot reach 8.8.8.8. Check your network connection.${NC}"
    exit 1
fi
echo ""

# 2. Check DNS resolution for STUN servers
echo -e "${YELLOW}[2/5] Checking DNS resolution for STUN servers...${NC}"
DNS_OK=0
for stun_addr in "${STUN_SERVERS[@]}"; do
    host=$(echo $stun_addr | cut -d: -f1)

    if host $host > /dev/null 2>&1; then
        ip=$(host $host | grep "has address" | head -1 | awk '{print $4}')
        echo -e "${GREEN}✓${NC} $host → $ip"
        DNS_OK=1
    else
        echo -e "${RED}✗${NC} $host → DNS resolution failed"
    fi
done

if [ $DNS_OK -eq 0 ]; then
    echo -e "${RED}All DNS lookups failed. Check your DNS configuration.${NC}"
    exit 1
fi
echo ""

# 3. Check UDP connectivity (ping test instead of netcat)
echo -e "${YELLOW}[3/5] Checking UDP connectivity (ping test)...${NC}"
for stun_addr in "${STUN_SERVERS[@]}"; do
    host=$(echo $stun_addr | cut -d: -f1)
    port=$(echo $stun_addr | cut -d: -f2)

    echo -n "Ping $host... "

    # Simple ICMP ping test (not UDP, but shows host is reachable)
    if ping -c 1 -W 1 $host > /dev/null 2>&1; then
        echo -e "${GREEN}OK${NC} (host reachable)"
    else
        echo -e "${YELLOW}NO ICMP${NC} (may still work via UDP)"
    fi
done
echo -e "${BLUE}Note: UDP STUN traffic cannot be tested with ping (ICMP only)${NC}"
echo ""

# 4. Check firewall rules
echo -e "${YELLOW}[4/5] Checking firewall rules...${NC}"
if command -v iptables > /dev/null 2>&1; then
    # Check if running as root
    if [ "$EUID" -eq 0 ]; then
        # Check for UDP blocks
        blocked=$(iptables -L -n -v | grep -E "DROP|REJECT" | grep -i udp | wc -l)
        if [ $blocked -gt 0 ]; then
            echo -e "${YELLOW}⚠${NC}  Found $blocked firewall rules blocking UDP"
            echo "   Review with: sudo iptables -L -n -v | grep UDP"
        else
            echo -e "${GREEN}✓${NC} No obvious UDP blocks in iptables"
        fi

        # Check for port-specific blocks
        for port in 3478 19302; do
            blocked=$(iptables -L -n -v | grep -E "DROP|REJECT" | grep "dpt:$port" | wc -l)
            if [ $blocked -gt 0 ]; then
                echo -e "${RED}✗${NC} Port $port is blocked by iptables"
            fi
        done
    else
        echo -e "${YELLOW}⚠${NC}  Not running as root - cannot check iptables"
        echo "   Run with sudo to check firewall: sudo $0"
    fi
else
    echo -e "${YELLOW}⚠${NC}  iptables not found (using firewalld or ufw?)"
fi
echo ""

# 5. Test with stun-client (if available)
echo -e "${YELLOW}[5/5] Testing STUN protocol (if stun-client available)...${NC}"
if command -v stun > /dev/null 2>&1; then
    for stun_addr in "${STUN_SERVERS[@]}"; do
        host=$(echo $stun_addr | cut -d: -f1)
        port=$(echo $stun_addr | cut -d: -f2)

        echo -n "STUN test: $host:$port... "

        # Run STUN client (timeout after 3 seconds)
        output=$(timeout 3 stun $host -p $port 2>&1 || true)

        if echo "$output" | grep -q "MappedAddress"; then
            ext_ip=$(echo "$output" | grep "MappedAddress" | awk '{print $3}')
            echo -e "${GREEN}SUCCESS${NC} (External IP: $ext_ip)"
        else
            echo -e "${RED}FAILED${NC}"
            echo "   Output: $output"
        fi
    done
else
    echo -e "${YELLOW}⚠${NC}  stun-client not installed - skipping STUN protocol tests"
    echo "   Install with: sudo apt-get install stun-client"
    echo ""
    echo -e "${BLUE}Manual STUN test:${NC}"
    echo "   stun stun.stunprotocol.org -p 3478"
fi
echo ""

# Summary
echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE} Diagnostic Summary${NC}"
echo -e "${BLUE}=========================================${NC}"
echo ""
echo -e "${GREEN}Recommendations:${NC}"
echo ""
echo "1. If DNS failed: Check /etc/resolv.conf"
echo "2. If UDP blocked: Check firewall settings"
echo "3. If STUN failed: May need to configure router/NAT"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo "- Install stun-client: sudo apt-get install stun-client"
echo "- Test manually: stun stun.stunprotocol.org -p 3478"
echo "- Check DNA Messenger logs for 'errno=101'"
echo ""
echo -e "${BLUE}Common errno codes:${NC}"
echo "  101 = ENETUNREACH (Network unreachable)"
echo "  111 = ECONNREFUSED (Connection refused)"
echo "  113 = EHOSTUNREACH (No route to host)"
echo ""
