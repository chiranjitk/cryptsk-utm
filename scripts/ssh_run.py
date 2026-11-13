import sys, os, paramiko
HOST='103.244.7.219'; PORT=22222; PW='CryptSK@123#$'
def client():
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, port=PORT, username='root', password=PW, timeout=30, banner_timeout=30, auth_timeout=30)
    return c
def run(cmd, timeout=180):
    c = client()
    _, out, err = c.exec_command(cmd, timeout=timeout)
    o = out.read().decode('utf-8','replace'); e = err.read().decode('utf-8','replace'); rc = out.channel.recv_exit_status()
    c.close(); return rc, o, e
if __name__ == '__main__':
    tmo = float(sys.argv[2]) if len(sys.argv) > 2 else 180
    rc, o, e = run(sys.argv[1], tmo)
    print(o); 
    if e.strip(): print('STDERR:', e[-800:], file=sys.stderr)
    sys.exit(rc)
