import os
import uuid
import subprocess
from flask import Flask, render_template, request, send_file, flash, redirect, url_for
from tempfile import mkdtemp
import threading
import paramiko

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Für Flash messages

CA_CERT_PATH = os.environ.get("CA_CERT_PATH", "/data/ca/ca.crt")
CA_KEY_PATH = os.environ.get("CA_KEY_PATH", "/data/ca/ca.key")
CRL_PATH = os.environ.get("CRL_PATH", "/data/ca/crl.pem")
CA_DIR = os.environ.get("CA_DIR","/data/ca")

SYNC_ENABLED = os.environ.get("SYNC_ENABLED", "false").lower() == "true"
SSH_HOST = os.environ.get("SSH_HOST", "")
SSH_USER = os.environ.get("SSH_USER", "")
SSH_PASS = os.environ.get("SSH_PASS", "")
SSH_PORT = int(os.environ.get("SSH_PORT", "22"))
REMOTE_CA_PATH = os.environ.get("REMOTE_CA_PATH", "/etc/nginx/certs/ca.crt")
REMOTE_CRL_PATH = os.environ.get("REMOTE_CRL_PATH", "/etc/nginx/certs/crl.pem")


def sync_to_npm():
    if not SYNC_ENABLED:
        return
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(SSH_HOST, port=SSH_PORT, username=SSH_USER, password=SSH_PASS)
        sftp = ssh.open_sftp()
        sftp.put(CA_CERT_PATH, REMOTE_CA_PATH)
        sftp.put(CRL_PATH, REMOTE_CRL_PATH)
        sftp.close()
        ssh.close()
        print("Sync to NPM succeeded")
    except Exception as e:
        print(f"Sync to NPM failed: {e}")


def generate_certificate(common_name: str):
    tmp_dir = mkdtemp()
    key_path = os.path.join(tmp_dir, "client.key")
    csr_path = os.path.join(tmp_dir, "client.csr")
    crt_path = os.path.join(tmp_dir, "client.crt")
    p12_path = os.path.join(tmp_dir, "client.p12")

    passphrase = str(uuid.uuid4())

    # 1. Private Key erzeugen
    subprocess.run(["openssl", "genrsa", "-out", key_path, "2048"], check=True)

    # 2. CSR erzeugen
    subprocess.run([
        "openssl", "req", "-new", "-key", key_path, "-out", csr_path,
        "-subj", f"/CN={common_name}"
    ], check=True)

    # 3. Zertifikat signieren (10 Jahre = 3650 Tage)
    subprocess.run([
        "openssl", "x509", "-req", "-in", csr_path, "-CA", CA_CERT_PATH,
        "-CAkey", CA_KEY_PATH, "-CAcreateserial", "-out", crt_path,
        "-days", "3650", "-sha256"
    ], check=True)

    # 4. PKCS#12 exportieren
    subprocess.run([
        "openssl", "pkcs12", "-export",
        "-out", p12_path,
        "-inkey", key_path,
        "-in", crt_path,
        "-certfile", CA_CERT_PATH,
        "-passout", f"pass:{passphrase}"
    ], check=True)

    # Start Sync in Thread
    threading.Thread(target=sync_to_npm, daemon=True).start()

    return p12_path, passphrase


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        cn = request.form.get("common_name")
        if not cn:
            flash("Common Name ist erforderlich.", "error")
            return redirect(url_for("index"))

        try:
            p12_path, passphrase = generate_certificate(cn)
            return render_template("passphrase.html", passphrase=passphrase, filename=os.path.basename(p12_path))
        except subprocess.CalledProcessError as e:
            flash(f"Fehler beim Erstellen des Zertifikats: {e}", "error")
            return redirect(url_for("index"))

    return render_template("index.html")


@app.route("/download/<filename>")
def download(filename):
    tmp_dir = os.path.join("/tmp")
    file_path = os.path.join(tmp_dir, filename)
    if not os.path.isfile(file_path):
        return "Datei nicht gefunden", 404
    return send_file(file_path, as_attachment=True)

def create_ca_if_not_exists():
    if not os.path.exists(CA_CERT_PATH) or not os.path.exists(CA_KEY_PATH):
        os.makedirs(CA_DIR, exist_ok=True)
        print("CA-Zertifikat und Schlüssel werden erzeugt...")

        subprocess.run([
            "openssl", "genrsa", "-out", CA_KEY_PATH, "4096"
        ], check=True)

        subprocess.run([
            "openssl", "req", "-x509", "-new", "-nodes",
            "-key", CA_KEY_PATH,
            "-sha256",
            "-days", "3650",
            "-out", CA_CERT_PATH,
            "-subj", "/CN=HomeAssistant-Local-CA"
        ], check=True)

        # Optional: CRL erstellen
        crl_path = os.path.join(CA_DIR, "crl.pem")
        subprocess.run([
            "openssl", "ca", "-gencrl",
            "-keyfile", CA_KEY_PATH,
            "-cert", CA_CERT_PATH,
            "-out", crl_path
        ], check=False)  # Wenn kein Index.txt, ignorieren

        print("CA wurde erstellt.")
    else:
        print("CA ist bereits vorhanden.")

if __name__ == "__main__":
    try:
        create_ca_if_not_exists()
    except subprocess.CalledProcessError as e:
        print(f"Fehler bei der CA-Erstellung: {e}")
        exit(1)

    app.run(host="0.0.0.0", port=5000)
