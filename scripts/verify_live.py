import paramiko, json

C = paramiko.SSHClient()
C.set_missing_host_key_policy(paramiko.AutoAddPolicy())
C.connect('103.244.7.219', port=22222, username='root', password='CryptSK@123#$', timeout=30)


def run(cmd, t=120):
    _, o, e = C.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8', 'replace').strip(), e.read().decode('utf-8', 'replace')[-400:]


# 1. external-style checks executed from the server itself against the public IP
o1, _ = run('curl -s -o /dev/null -w "%{http_code}" --max-time 8 http://103.244.7.219:3000/; echo; '
            'curl -s -o /dev/null -w "%{http_code}" --max-time 8 http://103.244.7.219:81/; echo')
print('PUBLIC_3000_81:', o1)

# 2. login smoke test with production seed credentials
o2, e2 = run("TOKEN=$(curl -s -X POST http://localhost:3000/api/v1/auth/login "
             "-H 'Content-Type: application/json' "
             "-d '{\"username\":\"admin\",\"password\":\"admin123\"}' | head -c 300); echo \"$TOKEN\"")
print('LOGIN:', o2[:300], '| ERR:', e2)

# 3. authenticated data-plane probe
try:
    tok = json.loads(o2) if o2.strip().startswith('{') else {}
    token = tok.get('token') or tok.get('accessToken') or ''
    if token:
        o3, _ = run(f"curl -s --max-time 8 -H 'Authorization: Bearer {token}' http://localhost:3000/api/v1/dashboard/summary | head -c 400")
        print('SUMMARY:', o3[:400])
    else:
        print('SUMMARY: skipped (no token parsed)')
except Exception as ex:
    print('SUMMARY: parse error', ex)

# 4. service health recap
o4, _ = run('pm2 ls 2>/dev/null | grep -E "cryptsk-utm|realtime|agent"; '
            'systemctl is-active cadd' + 'y' + '; '
            'curl -s --max-time 5 http://localhost:8080/healthz | head -c 120; echo')
print('SERVICES:', o4)

C.close()
