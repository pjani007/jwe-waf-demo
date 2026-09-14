#!/bin/bash
# provision.sh — one-time BIG-IP preparation for the JWE-WAF lab.
#
# RUN THIS ON THE BIG-IP, not on your laptop:
#   UDF -> bigip-waf -> Web Shell   (or SSH via the deployment's access method)
#   curl -s http://<your-host>/provision.sh | bash     # or paste it
#
# Provisioning ASM restarts services and can take several minutes. ILX is
# required because native iRules CRYPTO:: commands cannot do JWE — see
# docs/ARCHITECTURE.md.
set -euo pipefail

SELF_IP="${SELF_IP:-10.1.10.30/24}"
VLAN_NAME="${VLAN_NAME:-traffic}"
# UDF binds the traffic NIC at device index 1, which BIG-IP presents as 1.1.
# VERIFY with `tmsh show net interface` before trusting this.
TRAFFIC_IF="${TRAFFIC_IF:-1.1}"

echo "== current provisioning =="
tmsh list sys provision one-line | grep -E 'ltm|asm|ilx' || true

echo
echo "== provisioning ASM + ILX (nominal) =="
tmsh modify sys provision asm level nominal
tmsh modify sys provision ilx level nominal
echo "waiting for provisioning to settle (this is the slow part)..."
sleep 30
tmsh show sys mcp-state field-fmt | grep -E 'phase' || true

echo
echo "== interfaces visible to TMOS =="
tmsh show net interface

echo
echo "== VLAN + self-IP on the traffic subnet =="
# UDF assigns the traffic address in its CONTROL PLANE only; there is no DHCP
# on traffic subnets, so TMOS has to be told about it explicitly.
if tmsh list net vlan "$VLAN_NAME" >/dev/null 2>&1; then
  echo "vlan $VLAN_NAME exists"
else
  tmsh create net vlan "$VLAN_NAME" interfaces add "{ $TRAFFIC_IF { untagged } }"
  echo "created vlan $VLAN_NAME on $TRAFFIC_IF"
fi

if tmsh list net self "self_${VLAN_NAME}" >/dev/null 2>&1; then
  echo "self-IP self_${VLAN_NAME} exists"
else
  tmsh create net self "self_${VLAN_NAME}" address "$SELF_IP" vlan "$VLAN_NAME" \
    allow-service default
  echo "created self-IP $SELF_IP"
fi

tmsh save sys config

echo
echo "== verification =="
tmsh list sys provision one-line | grep -E 'asm|ilx'
tmsh list net self one-line
echo
echo "Reachability to the backend (must succeed before AS3):"
ping -c 2 -W 2 10.1.10.20 || echo "  BACKEND UNREACHABLE — check the backend netplan (udf/userdata/backend.sh)"

echo
echo "NEXT (from your laptop):"
echo "  python3 tools/ilx_deploy.py"
echo "  python3 tools/as3_submit.py bigip/as3/waf-jwe-declaration.json"
