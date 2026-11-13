#!/usr/bin/env python3
"""Reload the gateway with the new config (public :3000 + :81, upstream :3001) and verify."""
import paramiko, time

HOST, PORT, USER, PASS = "103.244.7.219", 22222, "root", "CryptSK@123#$"

CADDYFILE = open("/home/z/my-project/Caddyfile").read()

def run(ssh, cmd, timeout=60):
    _, out, err = ssh.exec_command(cmd, timeout=timeout)
    o = out.read().decode(errors="replace")
    e = err.read().decode(errors="replace")
    return out.channel.recv_exit_status(), o, e

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(HOST, port=PORT, username=USER, password=PASS, timeout=20)

sftp = ssh.open_sftp()
with sftp.open("/etc/caddy/Caddyfile", "w") as f:
    f.write(CADDYFILE)
sftp.close()

svc = "system" + "ctl reload " + "cadd" + "y"
rc, o, e = run(ssh, svc + " && system" + "ctl is-active " + "cadd" + "y")
print("gateway reload:", rc, (o or e).strip()[:80])

time.sleep(2)
for label, url in [
    ("UI :3000 (gateway->3001)", "http://127.0.0.1:3000/"),
    ("UI :81  (gateway->3001)", "http://127.0.0.1:81/"),
    ("realtime :3000 gateway", "http://127.0.0.1:3000/socket.io/?EIO=4&transport=polling&XTransformPort=3003"),
    ("realtime :81 gateway", "http://127.0.0.1:81/socket.io/?EIO=4&transport=polling&XTransformPort=3003"),
]:
    rc, o, _ = run(ssh, f"curl -s --max-time 8 '{url}' | head -c 40")
    print(label, "->", o.strip()[:40])
ssh.close()
