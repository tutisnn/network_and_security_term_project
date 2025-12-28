import socket
import json
import base64
import threading
import tkinter as tk
from tkinter import messagebox
from tkinter.scrolledtext import ScrolledText
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os

# ===============================
# GLOBAL VARIABLES
# ===============================
client_private_key = None
client_public_key = None
my_certificate = None
client2_certificate = None
master_key_km = None
session_key_ks = None
nonce_r1 = None

log_area = None
status_label = None
ca_host_entry = None

CLIENT_ID = "Client_1"
CA_HOST = None
CA_PORT = 5050
LISTEN_PORT = 5051

ca_host_entry = None
ca_port_entry = None
listen_port_entry = None

# ===============================
# LOG FUNCTION
# ===============================
def log(message):
    timestamp = datetime.now().strftime("%H:%M:%S")
    msg = f"[{timestamp}] {message}"
    print(msg)
    if log_area:
        log_area.insert(tk.END, msg + "\n")
        log_area.see(tk.END)

# ===============================
# STEP 1: GENERATE RSA KEYS
# ===============================
def generate_keys():
    global client_private_key, client_public_key

    log(f"[{CLIENT_ID}] Generating RSA key pair...")
    client_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    client_public_key = client_private_key.public_key()
    log(f"[{CLIENT_ID}] ✓ RSA key pair generated")
    
    # Log public key
    public_key_pem = client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    log(f"[{CLIENT_ID}] My Public Key PEM:\n{public_key_pem}")
    
    update_status("Keys Generated", "#27ae60")

# ===============================
# STEP 2: REQUEST CERTIFICATE
# ===============================
def request_certificate_from_ca():
    global my_certificate, CA_HOST, CA_PORT

    CA_HOST = ca_host_entry.get().strip()
    if not CA_HOST:
        messagebox.showerror("Error", "Please enter CA Host IP!")
        return
    
    try:
        CA_PORT = int(ca_port_entry.get())
    except:
        CA_PORT = 5050

    try:
        log(f"[{CLIENT_ID}] Connecting to CA at {CA_HOST}:{CA_PORT}")

        public_key_pem = client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        log(f"[{CLIENT_ID}] Sending public key to CA:\n{public_key_pem}")

        request = {
            "subject_id": CLIENT_ID,
            "public_key": public_key_pem
        }

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((CA_HOST, CA_PORT))
        s.send(json.dumps(request).encode())

        response = s.recv(8192).decode()
        my_certificate = json.loads(response)

        log(f"[{CLIENT_ID}] ✓ Certificate received from CA")
        log(f"[{CLIENT_ID}]   Subject ID: {my_certificate.get('Subject ID', 'N/A')}")
        log(f"[{CLIENT_ID}]   Serial Number: {my_certificate.get('Serial Number', 'N/A')}")
        log(f"[{CLIENT_ID}]   Valid From: {my_certificate.get('Validity Period', {}).get('Not Before', 'N/A')}")
        log(f"[{CLIENT_ID}]   Valid To: {my_certificate.get('Validity Period', {}).get('Not After', 'N/A')}")
        readable_cert = json.dumps(my_certificate, indent=2, ensure_ascii=False)
        log(f"[{CLIENT_ID}]   Full Certificate:\n{readable_cert}")

        s.close()
        update_status("Certificate Obtained", "#27ae60")
        messagebox.showinfo("Success", "Certificate obtained successfully")

    except Exception as e:
        log(f"[{CLIENT_ID}] ✗ CA error: {e}")
        import traceback
        log(f"[{CLIENT_ID}] Error traceback: {traceback.format_exc()}")
        messagebox.showerror("Error", str(e))

# ===============================
# STEP 3: LISTEN FOR CLIENT 2
# ===============================
def listen_for_client2():
    global LISTEN_PORT
    
    try:
        LISTEN_PORT = int(listen_port_entry.get())
    except:
        LISTEN_PORT = 5051
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", LISTEN_PORT))
        s.listen(1)

        log(f"[{CLIENT_ID}] Listening on port {LISTEN_PORT}")
        update_status("Waiting for Client 2", "#f39c12")

        conn, addr = s.accept()
        log(f"[{CLIENT_ID}] ✓ Client 2 connected from {addr[0]}:{addr[1]}")
        handle_client2(conn)

    except Exception as e:
        log(f"[{CLIENT_ID}] ✗ Server error: {e}")
        import traceback
        log(f"[{CLIENT_ID}] Error traceback: {traceback.format_exc()}")

# ===============================
# HANDLE CLIENT 2 (TAM GÜNCEL)
# ===============================
def handle_client2(conn):
    global nonce_r1, master_key_km, session_key_ks, client2_certificate

    try:
        # --- SERTİFİKA DEĞİŞİMİ ---
        log(f"[{CLIENT_ID}] Starting certificate exchange with Client 2...")
        conn.send(json.dumps(my_certificate).encode())
        log(f"[{CLIENT_ID}] ✓ Sent my certificate to Client 2")
        
        client2_data = conn.recv(8192).decode()
        client2_certificate = json.loads(client2_data)
        log(f"[{CLIENT_ID}] ✓ Received Client 2's certificate")
        log(f"[{CLIENT_ID}]   Client 2 Subject: {client2_certificate.get('Subject ID', 'N/A')}")
        log(f"[{CLIENT_ID}]   Client 2 Serial: {client2_certificate.get('Serial Number', 'N/A')}")
        
        readable_cert2 = json.dumps(client2_certificate, indent=2, ensure_ascii=False)
        log(f"[{CLIENT_ID}]   Client 2 Full Certificate:\n{readable_cert2}")

        # Client 2'nin Public Key'ini sertifikadan ayıklıyoruz
        client2_pub_pem = client2_certificate["Subject Public Key Info"]["Public Key Value"]
        client2_pub = serialization.load_pem_public_key(
            client2_pub_pem.encode(),
            backend=default_backend()
        )
        log(f"[{CLIENT_ID}] ✓ Extracted Client 2's public key")

        # --- PROTOKOL 1: MASTER KEY (Km) ELDE ETME --- 
        log(f"[{CLIENT_ID}] ========== Starting Master Key Protocol ==========")

        # Step 1: Send E(PUb, [N1 || IDa])
        nonce_r1 = os.urandom(16)
        payload1 = nonce_r1 + CLIENT_ID.encode()
        log(f"[{CLIENT_ID}] Step 1: Generating nonce N1: {nonce_r1.hex()}")
        log(f"[{CLIENT_ID}] Step 1: Payload = N1 || IDa (total length: {len(payload1)})")
        
        encrypted1 = client2_pub.encrypt(
            payload1,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        log(f"[{CLIENT_ID}] Step 1: Encrypted payload with RSA-OAEP (encrypted size: {len(encrypted1)} bytes)")
        conn.send(encrypted1)
        log(f"[{CLIENT_ID}] ✓ Step 1: N1 and IDa sent (RSA Encrypted)")

        # Step 2: Receive E(PUa, [N1 || N2])
        log(f"[{CLIENT_ID}] Step 2: Waiting for encrypted response E(PUa, [N1 || N2])...")
        encrypted2 = conn.recv(256)
        log(f"[{CLIENT_ID}] Step 2: Received encrypted data (size: {len(encrypted2)} bytes)")
        
        decrypted2 = client_private_key.decrypt(
            encrypted2,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        log(f"[{CLIENT_ID}] Step 2: Decrypted data (size: {len(decrypted2)} bytes)")
        
        received_n1 = decrypted2[:16]
        n2 = decrypted2[16:]
        log(f"[{CLIENT_ID}] Step 2: Extracted N1: {received_n1.hex()}")
        log(f"[{CLIENT_ID}] Step 2: Extracted N2: {n2.hex()}")
        
        if received_n1 != nonce_r1:
            log(f"[{CLIENT_ID}] ✗ N1 Verification FAILED!")
            log(f"[{CLIENT_ID}]   Expected N1: {nonce_r1.hex()}")
            log(f"[{CLIENT_ID}]   Received N1: {received_n1.hex()}")
            raise Exception("N1 Verification Failed!")
        log(f"[{CLIENT_ID}] ✓ Step 2: N1 verified successfully, N2 received")

        # Step 3: Send E(PUb, N2)
        log(f"[{CLIENT_ID}] Step 3: Encrypting N2 with Client 2's public key...")
        encrypted3 = client2_pub.encrypt(
            n2,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        log(f"[{CLIENT_ID}] Step 3: Encrypted N2 (size: {len(encrypted3)} bytes)")
        conn.send(encrypted3)
        log(f"[{CLIENT_ID}] ✓ Step 3: N2 verification sent back to Client 2")

        # Step 4: Send Signature and Encrypted Km
        log(f"[{CLIENT_ID}] Step 4: Generating Master Key Km...")
        master_key_km = os.urandom(32)
        log(f"[{CLIENT_ID}] Step 4: Generated Km: {master_key_km.hex()}")
        
        log(f"[{CLIENT_ID}] Step 4: Signing Km with my private key...")
        signature = client_private_key.sign(
            master_key_km,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        log(f"[{CLIENT_ID}] Step 4: Signature generated (size: {len(signature)} bytes)")
        
        log(f"[{CLIENT_ID}] Step 4: Encrypting Km with Client 2's public key...")
        encrypted_km = client2_pub.encrypt(
            master_key_km,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        log(f"[{CLIENT_ID}] Step 4: Encrypted Km (size: {len(encrypted_km)} bytes)")
        
        conn.send(signature + encrypted_km)
        log(f"[{CLIENT_ID}] ✓ Step 4: Signed Km and encrypted Km sent to Client 2")

        # --- PROTOKOL 2: SESSION KEY (Ks) DEĞİŞİMİ --- 
        log(f"[{CLIENT_ID}] ========== Starting Session Key Protocol ==========")
        
        # Step 1: Send IDa || N1
        log(f"[{CLIENT_ID}] Step 1: Generating session nonce N1...")
        n1_session = os.urandom(8).hex()
        log(f"[{CLIENT_ID}] Step 1: N1 (session) = {n1_session}")
        log(f"[{CLIENT_ID}] Step 1: Sending IDa || N1 to Client 2...")
        conn.send(f"{CLIENT_ID}||{n1_session}".encode())
        log(f"[{CLIENT_ID}] ✓ Step 1: IDa || N1 sent")

        # Step 2: Receive E(Km, [Ks || IDa || IDb || f(N1) || N2])
        log(f"[{CLIENT_ID}] Step 2: Waiting for encrypted session data E(Km, [Ks || IDa || IDb || f(N1) || N2])...")
        from cryptography.fernet import Fernet
        encrypted_session = conn.recv(4096)
        log(f"[{CLIENT_ID}] Step 2: Received encrypted session data (size: {len(encrypted_session)} bytes)")
        
        log(f"[{CLIENT_ID}] Step 2: Decrypting with Master Key Km...")
        km_fernet = Fernet(base64.urlsafe_b64encode(master_key_km))
        decrypted_session = json.loads(km_fernet.decrypt(encrypted_session).decode())
        
        session_key_ks = base64.b64decode(decrypted_session["Ks"])
        received_f_n1 = decrypted_session["f_n1"]
        n2_session = decrypted_session["n2"]
        
        log(f"[{CLIENT_ID}] Step 2: Decrypted session data:")
        log(f"[{CLIENT_ID}]   Ks: {session_key_ks.hex()}")
        log(f"[{CLIENT_ID}]   f(N1): {received_f_n1}")
        log(f"[{CLIENT_ID}]   N2: {n2_session}")

        # f(N1) Doğrulaması (Freshness/Güncellik kontrolü)
        log(f"[{CLIENT_ID}] Step 2: Verifying f(N1) freshness...")
        if received_f_n1 != n1_session + "_processed":
            log(f"[{CLIENT_ID}] ✗ f(N1) verification FAILED!")
            log(f"[{CLIENT_ID}]   Expected: {n1_session}_processed")
            log(f"[{CLIENT_ID}]   Received: {received_f_n1}")
            raise Exception("Session Step 2: f(N1) verification failed!")
        log(f"[{CLIENT_ID}] ✓ Step 2: f(N1) verified successfully")
        log(f"[{CLIENT_ID}] ✓ Step 2: Session Key Ks, f(N1), and N2 received and verified")

        # Step 3: Send E(Ks, f(N2))
        log(f"[{CLIENT_ID}] Step 3: Creating f(N2) confirmation...")
        ks_fernet = Fernet(base64.urlsafe_b64encode(session_key_ks))
        f_n2 = n2_session + "_confirmed"
        log(f"[{CLIENT_ID}] Step 3: f(N2) = {f_n2}")
        
        log(f"[{CLIENT_ID}] Step 3: Encrypting f(N2) with Session Key Ks...")
        encrypted_f_n2 = ks_fernet.encrypt(f_n2.encode())
        log(f"[{CLIENT_ID}] Step 3: Encrypted f(N2) (size: {len(encrypted_f_n2)} bytes)")
        
        conn.send(encrypted_f_n2)
        log(f"[{CLIENT_ID}] ✓ Step 3: f(N2) confirmation sent to Client 2")

        log(f"[{CLIENT_ID}] ========== Protocol Completed Successfully ==========")
        update_status("Session Key Ready", "#27ae60")
        messagebox.showinfo("Success", "Protocol completed successfully!")
        conn.close()

    except Exception as e:
        log(f"[{CLIENT_ID}] ✗ Exchange error: {e}")
        import traceback
        log(f"[{CLIENT_ID}] Error traceback: {traceback.format_exc()}")
        conn.close()

# ===============================
# UPDATE STATUS
# ===============================
def update_status(text, color):
    status_label.config(text=f"● {text}", fg=color)

# ===============================
# GUI SETUP
# ===============================
def setup_gui():
    global log_area, status_label, ca_host_entry, ca_port_entry, listen_port_entry
    
    root = tk.Tk()
    root.title("Client 1 - Certificate & Key Exchange")
    root.geometry("800x750")
    
    # Header
    header_frame = tk.Frame(root, bg="#3498db", height=80)
    header_frame.pack(fill=tk.X)
    header_frame.pack_propagate(False)
    
    title_label = tk.Label(
        header_frame,
        text="🔵 Client 1",
        fg="white",
        bg="#3498db",
        font=("Arial", 20, "bold")
    )
    title_label.pack(pady=20)
    
    # Status Frame
    status_frame = tk.Frame(root)
    status_frame.pack(fill=tk.X, padx=10, pady=10)
    
    status_label = tk.Label(
        status_frame,
        text="● Not Connected",
        fg="#95a5a6",
        font=("Arial", 12, "bold")
    )
    status_label.pack(side=tk.LEFT, padx=10)
    
    # Network Configuration Frame
    config_frame = tk.LabelFrame(
        root,
        text="Network Configuration",
        font=("Arial", 11, "bold"),
        padx=10,
        pady=10
    )
    config_frame.pack(fill=tk.X, padx=10, pady=10)
    
    # CA Host
    ca_frame = tk.Frame(config_frame)
    ca_frame.pack(fill=tk.X, pady=5)
    
    tk.Label(
        ca_frame,
        text="CA Host IP:",
        font=("Arial", 10),
        width=15,
        anchor="w"
    ).pack(side=tk.LEFT)
    
    ca_host_entry = tk.Entry(ca_frame, font=("Arial", 10), width=20)
    ca_host_entry.pack(side=tk.LEFT, padx=5)
    ca_host_entry.insert(0, "127.0.0.1")
    
    tk.Label(
        ca_frame,
        text="Port:",
        font=("Arial", 10)
    ).pack(side=tk.LEFT, padx=5)
    
    ca_port_entry = tk.Entry(ca_frame, font=("Arial", 10), width=10)
    ca_port_entry.pack(side=tk.LEFT, padx=5)
    ca_port_entry.insert(0, "5050")
    
    # My Listen Port
    listen_frame = tk.Frame(config_frame)
    listen_frame.pack(fill=tk.X, pady=5)
    
    tk.Label(
        listen_frame,
        text="My Listen Port:",
        font=("Arial", 10),
        width=15,
        anchor="w"
    ).pack(side=tk.LEFT)
    
    listen_port_entry = tk.Entry(listen_frame, font=("Arial", 10), width=10)
    listen_port_entry.pack(side=tk.LEFT, padx=5)
    listen_port_entry.insert(0, "5051")
    
    # My IP Display
    my_ip_frame = tk.Frame(config_frame)
    my_ip_frame.pack(fill=tk.X, pady=5)
    
    tk.Label(
        my_ip_frame,
        text="My IP Address:",
        font=("Arial", 10),
        width=15,
        anchor="w"
    ).pack(side=tk.LEFT)
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        local_ip = "Unable to detect"
    
    tk.Label(
        my_ip_frame,
        text=local_ip,
        font=("Arial", 10, "bold"),
        fg="#27ae60"
    ).pack(side=tk.LEFT, padx=5)
    
    # Control Buttons
    button_frame = tk.Frame(root)
    button_frame.pack(fill=tk.X, padx=10, pady=10)
    
    btn_generate = tk.Button(
        button_frame,
        text="1. Generate Keys",
        command=generate_keys,
        bg="#27ae60",
        fg="white",
        font=("Arial", 10, "bold"),
        relief=tk.FLAT,
        padx=15,
        pady=8
    )
    btn_generate.pack(side=tk.LEFT, padx=5)
    
    btn_cert = tk.Button(
        button_frame,
        text="2. Get Certificate from CA",
        command=request_certificate_from_ca,
        bg="#e67e22",
        fg="white",
        font=("Arial", 10, "bold"),
        relief=tk.FLAT,
        padx=15,
        pady=8
    )
    btn_cert.pack(side=tk.LEFT, padx=5)
    
    btn_connect = tk.Button(
        button_frame,
        text="3. Wait for Client 2",
        command=lambda: threading.Thread(target=listen_for_client2, daemon=True).start(),
        bg="#9b59b6",
        fg="white",
        font=("Arial", 10, "bold"),
        relief=tk.FLAT,
        padx=15,
        pady=8
    )
    btn_connect.pack(side=tk.LEFT, padx=5)
    
    # Certificate Info Frame
    cert_frame = tk.LabelFrame(
        root,
        text="Certificate Information",
        font=("Arial", 11, "bold"),
        padx=10,
        pady=10
    )
    cert_frame.pack(fill=tk.BOTH, padx=10, pady=5)
    
    cert_text = ScrolledText(cert_frame, height=8, bg="#ecf0f1", font=("Consolas", 9))
    cert_text.pack(fill=tk.BOTH, expand=True)
    
    def show_cert_info():
        cert_text.delete(1.0, tk.END)
        if my_certificate:
            cert_text.insert(tk.END, f"My Certificate:\n")
            cert_text.insert(tk.END, f"  Subject: {my_certificate['Subject ID']}\n")
            cert_text.insert(tk.END, f"  Serial: {my_certificate['Serial Number']}\n")
            cert_text.insert(tk.END, f"  Validity: {my_certificate['Validity Period']['Not After']}\n\n")
        

    
        if client2_certificate:
            cert_text.insert(tk.END, f"Client 2 Certificate:\n")
            cert_text.insert(tk.END, f"  Subject: {client2_certificate['Subject ID']}\n")
            cert_text.insert(tk.END, f"  Serial: {client2_certificate['Serial Number']}\n")
    
    btn_show_cert = tk.Button(
        cert_frame,
        text="Show Certificates",
        command=show_cert_info,
        bg="#3498db",
        fg="white",
        font=("Arial", 9),
        relief=tk.FLAT
    )
    btn_show_cert.pack(pady=5)
    
    # Log Section
    log_frame = tk.LabelFrame(
        root,
        text="Activity Log",
        font=("Arial", 11, "bold"),
        padx=10,
        pady=10
    )
    log_frame.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)
    
    log_area = ScrolledText(
        log_frame,
        width=90,
        height=15,
        bg="#ecf0f1",
        font=("Consolas", 9)
    )
    log_area.pack(fill=tk.BOTH, expand=True)
    
    return root

# ===============================
# MAIN
# ===============================
if __name__ == "__main__":
    root = setup_gui()
    log(f"[{CLIENT_ID}] Application started")
    log(f"[{CLIENT_ID}] Ready to begin certificate and key exchange process")
    log("")
    root.mainloop()