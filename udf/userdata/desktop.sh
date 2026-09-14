#!/bin/bash
# customUserdata for test-desktop (Ubuntu Desktop, 10.1.10.10).
# Same netplan caveat as the backend: the bound NIC arrives with no address.
set -euxo pipefail

TRAFFIC_IP=10.1.10.10/24

MGMT_IF=$(ip -o -4 route show default | awk '{print $5}' | head -1)
TRAFFIC_IF=$(ip -o link show | awk -F': ' '{print $2}' \
  | grep -E '^(ens|eth|enp)' | grep -v "^${MGMT_IF}$" | head -1)

cat > /etc/netplan/60-jwe-traffic.yaml <<EOF
network:
  version: 2
  ethernets:
    ${TRAFFIC_IF}:
      addresses: [${TRAFFIC_IP}]
EOF
chmod 600 /etc/netplan/60-jwe-traffic.yaml
netplan apply

apt-get update -y
apt-get install -y python3-pip python3-venv git curl jq

# The test harness runs from here. Clone the repo (or scp it), then:
#   python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
#   .venv/bin/python client/run_matrix.py --all
#
# keys/ must be present for the client to BUILD tokens. The client needs
# jwks.json (public) and shared-secrets.json (the profile-A symmetric key).
# It does NOT need the RSA private keys — those belong only on the BIG-IP.
echo "desktop prepared. Bring the repo across, create the venv, run the matrix."
