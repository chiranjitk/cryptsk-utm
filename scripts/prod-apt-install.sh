#!/usr/bin/env bash
# Provision the full UTM application stack from apt on the Cryptsk appliance.
# Heavy daemons are installed but NOT left running — the console manages them.
set -u
export DEBIAN_FRONTEND=noninteractive

echo "=== apt-get update ==="
apt-get update -qq

echo "=== installing UTM stack ==="
apt-get install -y --no-install-recommends \
  suricata clamav clamav-daemon clamav-freshclam \
  bind9 openvpn keepalived haproxy nginx \
  fail2ban auditd vnstat iftop conntrack rsyslog \
  bridge-utils ethtool vlan net-tools
echo "APT_RC=$?"

echo "=== daemon hygiene: install ≠ run ==="
for s in suricata clamav-freshclam clamav-daemon bind9 nginx haproxy \
         keepalived openvpn auditd postfix squid freeradius; do
  systemctl disable --now "$s" >/dev/null 2>&1
done
for s in rsyslog vnstat fail2ban; do
  systemctl enable --now "$s" >/dev/null 2>&1
done

echo "=== service states (suricata clamav nginx haproxy keepalived openvpn bind9 dnsmasq rsyslog vnstat fail2ban) ==="
systemctl is-active suricata clamav-daemon nginx haproxy keepalived openvpn bind9 dnsmasq rsyslog vnstat fail2ban 2>/dev/null | paste -sd' ' -

echo DONE
