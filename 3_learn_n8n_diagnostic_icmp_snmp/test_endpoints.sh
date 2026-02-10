#!/bin/bash

# Configuration
API_URL="http://localhost:5000"
USER="admin"
PASS="password"
TARGET_IP="127.0.0.1"

echo "=== Testing Network API ==="

# 1. Test ICMP Status
echo -e "\n[TEST 1] ICMP Status for $TARGET_IP"
curl -s -u "$USER:$PASS" -X POST "$API_URL/icmp/status" \
     -H "Content-Type: application/json" \
     -d "{\"ip\": \"$TARGET_IP\"}" | jq .

# 2. Test ICMP QoS
echo -e "\n[TEST 2] ICMP QoS for $TARGET_IP"
curl -s -u "$USER:$PASS" -X POST "$API_URL/icmp/qos" \
     -H "Content-Type: application/json" \
     -d "{\"ip\": \"$TARGET_IP\"}" | jq .

# 3. Test SNMP Data
echo -e "\n[TEST 3] SNMP Data for $TARGET_IP"
# Note: This might fail gracefully if SNMP is not running on localhost
curl -s -u "$USER:$PASS" -X POST "$API_URL/snmp/data" \
     -H "Content-Type: application/json" \
     -d "{\"ip\": \"$TARGET_IP\", \"community\": \"public\"}" | jq .

echo -e "\n[TEST 4] Invalid Auth"
curl -s -u "wrong:user" -X POST "$API_URL/icmp/status" \
     -H "Content-Type: application/json" \
     -d "{\"ip\": \"$TARGET_IP\"}"

echo -e "\n=== Test Complete ==="
