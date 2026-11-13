#!/usr/bin/env bash
# Cryptsk Console — production end-to-end test suite (runs on the appliance).
set -u
BASE=http://127.0.0.1:3000
API=$BASE/api/v1
CJ=/tmp/e2e-cookie.txt
rm -f $CJ
PASS=0; FAIL=0

ck(){ if [ "$2" = "$3" ]; then echo "PASS — $1"; PASS=$((PASS+1)); else echo "FAIL — $1 (expected [$2], got [$3])"; FAIL=$((FAIL+1)); fi; }
has(){ case "$2" in *"$3"*) echo "PASS — $1"; PASS=$((PASS+1));; *) echo "FAIL — $1 (missing: $3)"; FAIL=$((FAIL+1));; esac; }

echo "══ T1  UI serves"
code=$(curl -s -o /tmp/ui.html -w '%{http_code}' $BASE/)
ck "GET / → 200" 200 "$code"
has "UI brand present" "$(cat /tmp/ui.html)" "Cryptsk"

echo "══ T2  auth gate"
code=$(curl -s -o /dev/null -w '%{http_code}' $API/auth/me)
ck "unauthenticated /me → 401" 401 "$code"

echo "══ T3  login + cookie hygiene"
hdr=$(curl -si -c $CJ -X POST $API/auth/login -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin123"}')
code=$(printf '%s' "$hdr" | head -1 | awk '{print $2}')
ck "login POST → 200" 200 "$code"
secure=$(printf '%s' "$hdr" | grep -i '^set-cookie' | grep -ci 'secure' || true)
ck "session cookie has NO Secure flag (plain HTTP)" 0 "$secure"
has "Set-Cookie carries cryptsk_token" "$hdr" "cryptsk_token"

echo "══ T4  session"
me=$(curl -s -b $CJ $API/auth/me)
code=$(curl -s -o /dev/null -w '%{http_code}' -b $CJ $API/auth/me)
ck "/me → 200" 200 "$code"
has "/me role=super_admin" "$me" '"role":"super_admin"'

echo "══ T5  dashboard real telemetry (HostAdapter)"
sum=$(curl -s -b $CJ $API/dashboard/summary)
code=$(curl -s -o /dev/null -w '%{http_code}' -b $CJ $API/dashboard/summary)
ck "dashboard/summary → 200" 200 "$code"
has "summary contains throughput telemetry" "$sum" '"throughput"'
has "summary contains health block" "$sum" '"health"'
has "summary contains wan status" "$sum" '"wanStatus"'

echo "══ T6  system APIs + admin action"
code=$(curl -s -o /dev/null -w '%{http_code}' -b $CJ $API/system/status)
ck "system/status → 200" 200 "$code"
code=$(curl -s -o /dev/null -w '%{http_code}' -b $CJ -X POST $API/system/services/dnsmasq/restart -H 'Content-Type: application/json' -d '{}')
ck "service restart action (admin) → 200" 200 "$code"

echo "══ T7  realtime (socket.io on :3003, gateway :3000/:81)"
sid=$(curl -s --max-time 5 "http://127.0.0.1:3003/socket.io/?EIO=4&transport=polling" | head -c 60)
has "socket.io handshake (3003 direct)" "$sid" '{"sid"'
sid2=$(curl -s --max-time 5 "http://127.0.0.1:3000/socket.io/?EIO=4&transport=polling&XTransformPort=3003" | head -c 60)
has "socket.io handshake (:3000 via gateway)" "$sid2" '{"sid"'

echo "══ T8  agent data plane"
agent=$(curl -s --max-time 5 http://127.0.0.1:8080/healthz)
has "agent healthz ok" "$agent" '"ok":true'

echo "══ T9  webhook CRUD roundtrip"
name="e2e-$(date +%s)"
create=$(curl -s -b $CJ -X POST $API/webhooks -H 'Content-Type: application/json' \
  -d "{\"name\":\"$name\",\"url\":\"https://hooks.example.test/cryptsk\",\"events\":[\"alerts.new\"],\"enabled\":true}")
wid=$(printf '%s' "$create" | jq -r '.data.id // empty' 2>/dev/null)
if [ -n "$wid" ]; then echo "PASS — webhook created (id=$wid)"; PASS=$((PASS+1)); else echo "FAIL — webhook create returned no id: $(printf '%s' "$create" | head -c 160)"; FAIL=$((FAIL+1)); fi
list=$(curl -s -b $CJ $API/webhooks)
has "webhook listed" "$list" "$name"
code=$(curl -s -o /dev/null -w '%{http_code}' -b $CJ -X DELETE $API/webhooks/$wid)
ck "webhook DELETE → 200" 200 "$code"
list2=$(curl -s -b $CJ $API/webhooks)
case "$list2" in *"$name"*) echo "FAIL — webhook still present after delete"; FAIL=$((FAIL+1));; *) echo "PASS — webhook gone after delete"; PASS=$((PASS+1));; esac

echo "══ T10 audit trail in SQLite"
aud=$(sqlite3 /opt/cryptsk/console/db/cryptsk.db "select action from audit_log order by created_at desc limit 5" 2>/dev/null | tr '\n' ' ')
has "audit_log captured auth.login" "$aud" "auth.login"
has "audit_log captured webhook.create" "$aud" "webhook.create"
has "audit_log captured service.restart" "$aud" "service.restart"

echo "══ T11 UTM stack binaries (apt provisioning)"
for b in nft wg suricata clamdtop clamd clamscan ipsec openvpn squid nginx haproxy keepalived \
         named dnsmasq conntrack tcpdump tc iperf3 vnstat rsyslogd fail2ban-server freeradius; do
  if command -v "$b" >/dev/null 2>&1; then echo "PASS — binary $b"; PASS=$((PASS+1)); else echo "FAIL — binary $b missing"; FAIL=$((FAIL+1)); fi
done

echo "══ T12 firewall dataplane readable"
lines=$(nft list ruleset 2>/dev/null | wc -l)
if [ "$lines" -gt 0 ]; then echo "PASS — nftables ruleset readable ($lines lines)"; PASS=$((PASS+1)); else echo "FAIL — nftables ruleset empty/unreadable"; FAIL=$((FAIL+1)); fi
wg show >/dev/null 2>&1; ck "wg show executes" 0 "$?"

echo "══ Host health after provisioning"
free -m | head -2
df -h / | tail -1

echo "══ RESULT: $PASS passed, $FAIL failed"
exit $FAIL
