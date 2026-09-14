#!/bin/bash
# customUserdata for api-backend (Ubuntu Server, 10.1.10.20).
#
# Set this as the component's Custom Userdata in UDF, or paste it into the web
# shell after first boot.
#
# THE NETPLAN BLOCK IS NOT OPTIONAL. Binding an interface in UDF assigns the
# address in UDF's control plane only: the NIC is attached but has NO IP,
# because UDF's own userdata writes netplan with the management NIC alone and
# there is no DHCP on traffic subnets.
set -euxo pipefail

TRAFFIC_IP=10.1.10.20/24

# The traffic NIC is the non-management one; discover it rather than guessing
# ens6, which varies with instance shape.
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
apt-get install -y python3-pip python3-venv

install -d -m 755 /opt/jwe-lab
python3 -m venv /opt/jwe-lab/.venv
/opt/jwe-lab/.venv/bin/pip install -q fastapi uvicorn pydantic

# app.py and jwks.json are copied here by the operator:
#   scp -P <sshPort> backend/app.py  ubuntu@<dnsKey>.access.udf.f5.com:/tmp/
#   scp -P <sshPort> keys/jwks.json  ubuntu@<dnsKey>.access.udf.f5.com:/tmp/
#   sudo mv /tmp/app.py /tmp/jwks.json /opt/jwe-lab/
# Only the PUBLIC jwks.json goes here. Never copy the private keyring or
# shared-secrets.json to the backend — the BIG-IP is the only recipient.

cat > /etc/systemd/system/jwe-backend.service <<'EOF'
[Unit]
Description=JWE-WAF lab backend
After=network-online.target

[Service]
WorkingDirectory=/opt/jwe-lab
Environment=JWKS_PATH=/opt/jwe-lab/jwks.json
ExecStart=/opt/jwe-lab/.venv/bin/uvicorn app:app --host 0.0.0.0 --port 8080
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable jwe-backend
# Started once app.py is in place:
#   sudo systemctl start jwe-backend && curl -s localhost:8080/healthz
echo "backend prepared. Copy app.py + jwks.json to /opt/jwe-lab, then start jwe-backend."
