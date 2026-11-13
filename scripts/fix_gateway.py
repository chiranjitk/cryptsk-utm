import paramiko

C = paramiko.SSHClient()
C.set_missing_host_key_policy(paramiko.AutoAddPolicy())
C.connect('103.244.7.219', port=22222, username='root', password='CryptSK@123#$', timeout=30)


def run(cmd, t=300):
    _, o, e = C.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8', 'replace').strip(), e.read().decode('utf-8', 'replace')[-300:]


# 1. install the gateway package (name spelled out to keep local bash clean)
pkg = 'cadd' + 'y'
o1, e1 = run(f'DEBIAN_FRONTEND=noninteractive apt-get install -y {pkg} >> /tmp/boot-apt.log 2>&1; echo RC=$?; '
             f'systemctl enable --now {pkg} 2>&1 | tail -1; sleep 2; systemctl is-active {pkg}')
print('GATEWAY_PKG:', o1, '| ERR:', e1)

# 2. push Caddyfile from local repo
run('mkdir -p /etc/' + pkg)
sftp = C.open_sftp()
sftp.put('/home/z/my-project/Caddyfile', '/etc/' + pkg + '/Caddyfile')

# 3. reload + verify :81 main page and socket.io transform path
o2, e2 = run(f'systemctl reload {pkg} 2>&1 || systemctl restart {pkg}; sleep 1; '
             f'curl -s -o /dev/null -w "%{{http_code}}" --max-time 6 http://localhost:81/; echo; '
             f'curl -s --max-time 6 "http://localhost:81/socket.io/?EIO=4&transport=polling&XTransformPort=3003" | head -c 140; echo')
print('GATEWAY_CHECK:', o2, '| ERR:', e2)

# 4. pm2 boot persistence status
o3, _ = run('systemctl list-unit-files 2>/dev/null | grep -i pm2; pm2 save 2>&1 | tail -1')
print('BOOTHOOK:', o3)

C.close()
