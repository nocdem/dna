#!/bin/bash
# Bootstrap Node Monitoring Script
# Checks health and status of DHT bootstrap nodes
# Usage: ./monitor-bootstrap.sh [ip_address]
#        ./monitor-bootstrap.sh all

set -e

# Bootstrap node list
declare -A BOOTSTRAP_NODES=(
    ["dna-bootstrap-us-1"]="154.38.182.161"
    ["dna-bootstrap-eu-1"]="164.68.105.227"
    ["dna-bootstrap-eu-2"]="164.68.116.180"
)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to check single node
check_node() {
    local hostname=$1
    local ip=$2

    echo ""
    echo "============================================"
    echo -e "${BLUE}Checking: $hostname ($ip)${NC}"
    echo "============================================"

    # 1. Check SSH connectivity
    echo -n "SSH Connection:       "
    if ssh -o ConnectTimeout=5 root@$ip "exit" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Connected${NC}"
    else
        echo -e "${RED}✗ Failed${NC}"
        echo "  Cannot connect to root@$ip"
        return 1
    fi

    # 2. Check systemd service status
    echo -n "Service Status:       "
    if ssh root@$ip "systemctl is-active --quiet dna-dht-bootstrap.service" 2>/dev/null; then
        echo -e "${GREEN}✓ Running${NC}"
    else
        echo -e "${RED}✗ Stopped${NC}"
        ssh root@$ip "systemctl status dna-dht-bootstrap.service --no-pager | tail -5" 2>/dev/null || true
        return 1
    fi

    # 3. Check process
    echo -n "DHT Process:          "
    local pid=$(ssh root@$ip "pgrep -f persistent_bootstrap" 2>/dev/null | head -1)
    if [ -n "$pid" ]; then
        echo -e "${GREEN}✓ Running (PID: $pid)${NC}"
    else
        echo -e "${RED}✗ Not running${NC}"
        return 1
    fi

    # 4. Check uptime
    echo -n "Service Uptime:       "
    local uptime=$(ssh root@$ip "systemctl show dna-dht-bootstrap.service --property=ActiveEnterTimestampMonotonic --value" 2>/dev/null)
    if [ -n "$uptime" ] && [ "$uptime" != "0" ]; then
        local uptime_human=$(ssh root@$ip "systemctl status dna-dht-bootstrap.service --no-pager | grep 'Active:' | sed 's/.*Active: //' | sed 's/ ago.*//' | awk '{print \$1, \$2}'" 2>/dev/null)
        echo -e "${GREEN}$uptime_human${NC}"
    else
        echo -e "${YELLOW}Unknown${NC}"
    fi

    # 5. Check DHT port (4000)
    echo -n "DHT Port (4000/UDP):  "
    if ssh root@$ip "ss -ulnp | grep -q ':4000 '" 2>/dev/null; then
        echo -e "${GREEN}✓ Listening${NC}"
    else
        echo -e "${RED}✗ Not listening${NC}"
        return 1
    fi

    # 6. Check system resources
    echo -n "System Load:          "
    local load=$(ssh root@$ip "uptime | awk -F'load average:' '{print \$2}' | awk '{print \$1}' | tr -d ','" 2>/dev/null)
    if [ -n "$load" ]; then
        echo -e "${GREEN}$load${NC}"
    else
        echo -e "${YELLOW}Unknown${NC}"
    fi

    # 7. Check memory usage
    echo -n "Memory Usage:         "
    local mem=$(ssh root@$ip "free -h | awk '/^Mem:/ {print \$3 \"/\" \$2}'" 2>/dev/null)
    if [ -n "$mem" ]; then
        echo -e "${GREEN}$mem${NC}"
    else
        echo -e "${YELLOW}Unknown${NC}"
    fi

    # 8. Check disk usage
    echo -n "Disk Usage (/):       "
    local disk=$(ssh root@$ip "df -h / | awk 'NR==2 {print \$3 \"/\" \$2 \" (\" \$5 \")\"}'" 2>/dev/null)
    if [ -n "$disk" ]; then
        echo -e "${GREEN}$disk${NC}"
    else
        echo -e "${YELLOW}Unknown${NC}"
    fi

    # 9. Check recent logs for errors
    echo -n "Recent Errors:        "
    local errors=$(ssh root@$ip "journalctl -u dna-dht-bootstrap.service --since '5 minutes ago' | grep -i error | wc -l" 2>/dev/null)
    if [ -n "$errors" ]; then
        if [ "$errors" -eq 0 ]; then
            echo -e "${GREEN}0 (last 5 minutes)${NC}"
        else
            echo -e "${YELLOW}$errors (last 5 minutes)${NC}"
        fi
    else
        echo -e "${YELLOW}Unknown${NC}"
    fi

    # 10. Check last restart
    echo -n "Last Restart:         "
    local restart_time=$(ssh root@$ip "systemctl show dna-dht-bootstrap.service --property=ExecMainStartTimestamp --value" 2>/dev/null)
    if [ -n "$restart_time" ] && [ "$restart_time" != "n/a" ]; then
        echo -e "${GREEN}$restart_time${NC}"
    else
        echo -e "${YELLOW}Unknown${NC}"
    fi

    echo ""
    echo -e "${GREEN}✓ $hostname is healthy${NC}"
    return 0
}

# Main script
if [ "$#" -eq 0 ] || [ "$1" = "all" ]; then
    echo "============================================"
    echo "DNA DHT Bootstrap Network Monitor"
    echo "============================================"
    echo "Checking all bootstrap nodes..."

    healthy=0
    unhealthy=0

    for hostname in "${!BOOTSTRAP_NODES[@]}"; do
        ip="${BOOTSTRAP_NODES[$hostname]}"
        if check_node "$hostname" "$ip"; then
            ((healthy++))
        else
            ((unhealthy++))
        fi
    done

    echo ""
    echo "============================================"
    echo "Network Status Summary"
    echo "============================================"
    echo -e "Healthy Nodes:   ${GREEN}$healthy${NC}"
    echo -e "Unhealthy Nodes: ${RED}$unhealthy${NC}"
    echo -e "Total Nodes:     $(( healthy + unhealthy ))"
    echo ""

    if [ $unhealthy -eq 0 ]; then
        echo -e "${GREEN}✓ All bootstrap nodes are healthy${NC}"
        exit 0
    else
        echo -e "${YELLOW}⚠ Some bootstrap nodes need attention${NC}"
        exit 1
    fi

elif [ "$#" -eq 1 ]; then
    ip=$1

    # Check if it's a hostname from our list
    if [ -n "${BOOTSTRAP_NODES[$ip]}" ]; then
        check_node "$ip" "${BOOTSTRAP_NODES[$ip]}"
    else
        # Assume it's an IP address
        check_node "custom" "$ip"
    fi
else
    echo "Usage: $0 [ip_address|hostname|all]"
    echo ""
    echo "Examples:"
    echo "  $0                              # Check all bootstrap nodes"
    echo "  $0 all                          # Check all bootstrap nodes"
    echo "  $0 dna-bootstrap-us-1           # Check specific node by hostname"
    echo "  $0 154.38.182.161               # Check specific node by IP"
    echo ""
    echo "Available bootstrap nodes:"
    for hostname in "${!BOOTSTRAP_NODES[@]}"; do
        echo "  $hostname  ${BOOTSTRAP_NODES[$hostname]}"
    done
    exit 1
fi
