import os
import subprocess
from flask import Flask, request, send_file, jsonify
import uuid
import tempfile

app = Flask(__name__)

# Pfade für CA
CA_DIR = "/data/ca"
CA_CERT_PATH = os.path.join(CA_DIR, "ca.crt")
CA_KEY_PATH = os.path.join(CA_DIR, "ca.key")
CA_SERIAL_PATH = os.path.join(CA_DIR, "ca.srl")

def create_ca_if_not_exists():
    if not os.path.exists(CA_CERT_PATH) or not os.path.exists(CA_KEY_PATH):
        os.makedirs(CA_DIR, exist_ok=True)
        print("Erstelle CA Zertifikat und Schlüssel...")

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

        # Leere Serial-Datei für openssl
        if not os.path.exists(CA_SERIAL_PATH):
            with open(CA_SERIAL_PATH, "w") as f:
                f.write("01")

        print("CA wurde erstellt.")
    else:
        print("CA Zertifikat und Schlüssel vorhanden.")

def sign_certificate(csr_pem: bytes, out_path: str):
    with tempfile.NamedTemporaryFile(delete=True) as csr_file:
        csr_file.write(csr_pem)
        csr_file.flush()

        subprocess.run([
            "openssl", "x509", "-req",
            "-in", csr_file.name,
            "-CA", CA_CERT_PATH,
            "-CAkey", CA_KEY_PATH,
            "-CAserial", CA_SERIAL_PATH,
            "-CAcreateserial",
            "-out", out_path,
            "-days", "3650",
            "-sha256"
        ], check=True)

@app.route("/ca.crt", methods=["GET"])
def download_ca():
    if not os.path.exists(CA_CERT_PATH):
        return "CA Certificate not found", 404
    return send_file(CA_CERT_PATH, mimetype="application/x-x509-ca-cert", as_attachment=True)

@app.route("/sign", methods=["POST"])
def sign():
    """
    Erwarte JSON mit "csr" Base64 oder PEM-encoded CSR.
    Signiere und sende das Zertifikat als Datei zurück.
    """

    data = request.json
    if not data or "csr" not in data:
        return jsonify({"error": "Missing 'csr' field"}), 400

    csr_pem = data["csr"].encode("utf-8")

    cert_out_path = os.path.join("/tmp", f"cert_{uuid.uuid4()}.crt")
    try:
        sign_certificate(csr_pem, cert_out_path)
        return send_file(cert_out_path, mimetype="application/x-x509-user-cert", as_attachment=True, download_name="signed_cert.crt")
    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"OpenSSL error: {e}"}), 500
    finally:
        if os.path.exists(cert_out_path):
            os.remove(cert_out_path)

if __name__ == "__main__":
    create_ca_if_not_exists()
    app.run(host="0.0.0.0", port=5000)
