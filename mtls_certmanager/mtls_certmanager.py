from flask import Flask, render_template, request, send_file, redirect, url_for
import os
import subprocess
import paramiko

app = Flask(__name__)

CA_KEY = 'ca.key'
CA_CERT = 'ca.crt'
CRL_FILE = 'crl.pem'
CERTS_DIR = 'certs'

os.makedirs(CERTS_DIR, exist_ok=True)

def ensure_ca():
    if not os.path.exists(CA_KEY) or not os.path.exists(CA_CERT):
        subprocess.run(['openssl', 'genrsa', '-aes256', '-passout', 'pass:changeme', '-out', CA_KEY, '4096'])
        subprocess.run(['openssl', 'req', '-new', '-x509', '-days', '3650', '-key', CA_KEY, '-passin', 'pass:changeme',
                        '-out', CA_CERT, '-subj', '/CN=HomeAssistant-CA'])
        subprocess.run(['openssl', 'ca', '-gencrl', '-keyfile', CA_KEY, '-cert', CA_CERT, '-out', CRL_FILE,
                        '-passin', 'pass:changeme'])

def sync_to_npm(npm_host, npm_user, npm_password, remote_path):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(npm_host, username=npm_user, password=npm_password)
    sftp = ssh.open_sftp()
    sftp.put(CA_CERT, f"{remote_path}/ca.crt")
    sftp.put(CRL_FILE, f"{remote_path}/crl.pem")
    sftp.close()
    ssh.exec_command("docker restart npm_app")
    ssh.close()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/create_cert', methods=['POST'])
def create_cert():
    cn = request.form['common_name']
    key_file = f"{CERTS_DIR}/{cn}.key"
    csr_file = f"{CERTS_DIR}/{cn}.csr"
    crt_file = f"{CERTS_DIR}/{cn}.crt"
    subprocess.run(['openssl', 'genrsa', '-out', key_file, '2048'])
    subprocess.run(['openssl', 'req', '-new', '-key', key_file, '-out', csr_file, '-subj', f"/CN={cn}"])
    subprocess.run(['openssl', 'x509', '-req', '-in', csr_file, '-CA', CA_CERT, '-CAkey', CA_KEY, '-CAcreateserial',
                    '-out', crt_file, '-days', '365', '-passin', 'pass:changeme'])
    return redirect(url_for('index'))

@app.route('/sync', methods=['POST'])
def sync():
    npm_host = request.form['npm_host']
    npm_user = request.form['npm_user']
    npm_password = request.form['npm_password']
    remote_path = request.form['remote_path']
    sync_to_npm(npm_host, npm_user, npm_password, remote_path)
    return redirect(url_for('index'))

@app.route('/download/<filename>')
def download(filename):
    return send_file(os.path.join(CERTS_DIR, filename), as_attachment=True)

if __name__ == '__main__':
    ensure_ca()
    app.run(host='0.0.0.0', port=5000)
