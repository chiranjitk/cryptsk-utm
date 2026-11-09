#!/usr/bin/env python3
"""Cutover: Caddy takes public :3000 as the gateway, Next moves to :3001 (ADR-008)."""
import paramiko

HOST, PORT, USER, PASS = "103.244.7.219", 22222, "root", "CryptSK@123#$"

CADDYFILE = open("/home/z/my-project/Caddyfile").read()

def run(ssh, cmd, timeout=90):
    _, out, err = ssh.exec_command(cmd, timeout=timeout)
    o = out.read().decode(errors="replace")
    e = err.read().decode(errors="replace")
    rc = out.channel.recv_exit_status()
    return rc, o, e

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(HOST, port=PORT, username=USER, password=PASS, timeout=20)

# 1) stop Next on :3000 (frees the public port)
rc, o, _ = run(ssh, "pm2 stop cryptsk-utm")
print("pm2 stop:", rc, (o or "").strip()[:80])

# 2) install the new gateway config (now owns :3000 and :81)
sftp = ssh.open_sftp()
with sftp.open("/etc/caddy/Caddyfile", "w") as f:
    f.write(CADDYFILE)
sftp.close()
rc, o, e = run(ssh, "systemctl reload gw && systemctl is-active gw", timeout=30)
print("gateway reload:", rc, (o or e or "").strip()[:80])

# 3) move Next behind the gateway on :3001
rc, o, _ = run(ssh, "pm2 delete cryptsk-utm 2>/dev/null; "
                   "cd /opt/cryptsk/console && NODE_ENV=production pm2 start "
                   "./node_modules/next/dist/bin/next --name cryptsk-utm -- start -p 3001 && pm2 save", timeout=60)
print("next on 3001:", rc, (o or "").strip()[:200])

import time; time.sleep(6)

# 4) verify all planes
for label, url in [
    ("UI :3000 (gateway->3001)", "http://127.0.0.1:3000/"),
    ("UI :3001 (next direct)", "http://127.0.0.1:3001/"),
    ("UI :81  (gateway->3001)", "http://127.0.0.1:81/"),
]:
    rc, o, _ = run(ssh, f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 8 {url}")
    print(label, "->", o.strip())

for label, url in [
    ("realtime :3000 gateway", "http://127.0.0.1:3000/socket.io/?EIO=4&transport=polling&XTransformPort=3003"),
    ("realtime :81 gateway  ", "http://127.0.0.1:81/socket.io/?EIO=4&transport=polling&XTransformPort=3003"),
    ("realtime :3003 direct ", "http://127.0.0.1:3003/socket.io/?EIO=4&transport=polling"),
]:
    rc, o, _ = run(ssh, f"curl -s --max-time 8 '{url}' | head -c 30")
    print(label, "->", o.strip()[:30])

rc, o, _ = run(ssh, "pm2 ls")
print(o)
ssh.close()
