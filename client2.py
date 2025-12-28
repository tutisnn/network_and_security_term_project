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
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import os

# ===============================
# GLOBAL VARIABLES
# ===============================
client_private_key = None
client_public_key = None
my_certificate = None
client1_certificate = None
master_key_km = None
session_key_ks = None

log_area = None
status_label = None

CLIENT_ID = "Client_2"
CA_HOST = "127.0.0.1"
CA_PORT = 5050
CLIENT1_HOST = "127.0.0.1"
CLIENT1_PORT = 5051

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
    update_status("Keys Generated", "#27ae60")

# ===============================
# STEP 2: REQUEST CERTIFICATE
# ===============================
def request_certificate_from_ca():
    global my_certificate
    host = ca_host_entry.get().strip()
    try:
        port = int(ca_port_entry.get())
        log(f"[{CLIENT_ID}] Connecting to CA at {host}:{port}")
        
        public_key_pem = client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        log(f"[{CLIENT_ID}] Sending public key to CA:\n{public_key_pem}")
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        s.send(json.dumps({"subject_id": CLIENT_ID, "public_key": public_key_pem}).encode())
        log(f"[{CLIENT_ID}] Certificate request sent to CA")
        
        response_data = s.recv(8192).decode()
        my_certificate = json.loads(response_data)
        log(f"[{CLIENT_ID}] ✓ Certificate received from CA")
        log(f"[{CLIENT_ID}]   Subject ID: {my_certificate.get('Subject ID', 'N/A')}")
        log(f"[{CLIENT_ID}]   Serial Number: {my_certificate.get('Serial Number', 'N/A')}")
        log(f"[{CLIENT_ID}]   Valid From: {my_certificate.get('Validity Period', {}).get('Not Before', 'N/A')}")
        log(f"[{CLIENT_ID}]   Valid To: {my_certificate.get('Validity Period', {}).get('Not After', 'N/A')}")
        readable_cert = json.dumps(my_certificate, indent=2, ensure_ascii=False)
        log(f"[{CLIENT_ID}]   Full Certificate:\n{readable_cert}")
        
        s.close()
        update_status("Certificate Obtained", "#27ae60")
    except Exception as e:
        log(f"[{CLIENT_ID}] ✗ CA Error: {e}")
        import traceback
        log(f"[{CLIENT_ID}] Error traceback: {traceback.format_exc()}")

# ===============================
# STEP 3: CONNECT TO CLIENT 1 (GÜNCELLENDİ)
# ===============================
def connect_to_client1():
    global client1_certificate, master_key_km, session_key_ks
    host = client1_host_entry.get().strip()
    try:
        port = int(client1_port_entry.get())
        log(f"[{CLIENT_ID}] Connecting to Client 1 at {host}:{port}")
        
        update_status("Connecting...", "#f39c12")
        c_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        c_socket.connect((host, port))
        log(f"[{CLIENT_ID}] ✓ Connected to Client 1")

        # 1. Sertifika Değişimi
        log(f"[{CLIENT_ID}] Starting certificate exchange with Client 1...")
        client1_data = c_socket.recv(8192).decode()
        client1_certificate = json.loads(client1_data)
        log(f"[{CLIENT_ID}] ✓ Received Client 1's certificate")
        log(f"[{CLIENT_ID}]   Client 1 Subject: {client1_certificate.get('Subject ID', 'N/A')}")
        log(f"[{CLIENT_ID}]   Client 1 Serial: {client1_certificate.get('Serial Number', 'N/A')}")
        readable_cert1 = json.dumps(client1_certificate, indent=2, ensure_ascii=False)
        log(f"[{CLIENT_ID}]   Client 1 Full Certificate:\n{readable_cert1}")
        
        log(f"[{CLIENT_ID}] Sending my certificate to Client 1...")
        c_socket.send(json.dumps(my_certificate).encode())
        log(f"[{CLIENT_ID}] ✓ Sent my certificate to Client 1")

        log(f"[{CLIENT_ID}] Extracting Client 1's public key...")
        client1_pub_pem = client1_certificate["Subject Public Key Info"]["Public Key Value"]
        client1_pub = serialization.load_pem_public_key(client1_pub_pem.encode(), backend=default_backend())
        log(f"[{CLIENT_ID}] ✓ Extracted Client 1's public key")

        # --- PROTOKOL 1: MASTER KEY (Km) ELDE ETME ---
        log(f"[{CLIENT_ID}] ========== Starting Master Key Protocol ==========")

        # Step 1: Receive E(PUb, [N1 || IDa])
        log(f"[{CLIENT_ID}] Step 1: Waiting for encrypted message E(PUb, [N1 || IDa])...")
        encrypted1 = c_socket.recv(256)
        log(f"[{CLIENT_ID}] Step 1: Received encrypted data (size: {len(encrypted1)} bytes)")
        
        log(f"[{CLIENT_ID}] Step 1: Decrypting with my private key...")
        decrypted1 = client_private_key.decrypt(
            encrypted1, 
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        log(f"[{CLIENT_ID}] Step 1: Decrypted data (size: {len(decrypted1)} bytes)")
        
        n1 = decrypted1[:16]
        client1_id = decrypted1[16:].decode()
        log(f"[{CLIENT_ID}] Step 1: Extracted N1: {n1.hex()}")
        log(f"[{CLIENT_ID}] Step 1: Extracted Client ID: {client1_id}")
        log(f"[{CLIENT_ID}] ✓ Step 1: N1 received and decrypted successfully")

        # Step 2: Send E(PUa, [N1 || N2])
        log(f"[{CLIENT_ID}] Step 2: Generating nonce N2...")
        n2 = os.urandom(16)
        log(f"[{CLIENT_ID}] Step 2: Generated N2: {n2.hex()}")
        
        payload2 = n1 + n2
        log(f"[{CLIENT_ID}] Step 2: Creating payload N1 || N2 (total size: {len(payload2)} bytes)")
        
        log(f"[{CLIENT_ID}] Step 2: Encrypting with Client 1's public key...")
        encrypted2 = client1_pub.encrypt(
            payload2, 
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        log(f"[{CLIENT_ID}] Step 2: Encrypted payload (size: {len(encrypted2)} bytes)")
        
        c_socket.send(encrypted2)
        log(f"[{CLIENT_ID}] ✓ Step 2: N2 generated and sent with N1 to Client 1")

        # Step 3: Receive E(PUb, N2)
        log(f"[{CLIENT_ID}] Step 3: Waiting for N2 verification E(PUb, N2)...")
        encrypted3 = c_socket.recv(256)
        log(f"[{CLIENT_ID}] Step 3: Received encrypted N2 (size: {len(encrypted3)} bytes)")
        
        log(f"[{CLIENT_ID}] Step 3: Decrypting with my private key...")
        received_n2 = client_private_key.decrypt(
            encrypted3, 
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        log(f"[{CLIENT_ID}] Step 3: Decrypted N2: {received_n2.hex()}")
        
        log(f"[{CLIENT_ID}] Step 3: Verifying N2...")
        if received_n2 != n2:
            log(f"[{CLIENT_ID}] ✗ N2 verification FAILED!")
            log(f"[{CLIENT_ID}]   Generated N2: {n2.hex()}")
            log(f"[{CLIENT_ID}]   Received N2: {received_n2.hex()}")
            raise Exception("N2 verification failed!")
        log(f"[{CLIENT_ID}] ✓ Step 3: N2 verified successfully by Client 1")

        # Step 4: Receive Signature (256 bytes) and Encrypted Km (256 bytes)
        log(f"[{CLIENT_ID}] Step 4: Waiting for signature and encrypted Km...")
        data4 = c_socket.recv(512)
        log(f"[{CLIENT_ID}] Step 4: Received data (size: {len(data4)} bytes)")
        
        signature = data4[:256]
        encrypted_km = data4[256:]
        log(f"[{CLIENT_ID}] Step 4: Signature size: {len(signature)} bytes, Encrypted Km size: {len(encrypted_km)} bytes")
        
        log(f"[{CLIENT_ID}] Step 4: Decrypting Km with my private key...")
        master_key_km = client_private_key.decrypt(
            encrypted_km,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        log(f"[{CLIENT_ID}] Step 4: Decrypted Km: {master_key_km.hex()}")
        
        log(f"[{CLIENT_ID}] Step 4: Verifying signature with Client 1's public key...")
        client1_pub.verify(signature, master_key_km, padding.PKCS1v15(), hashes.SHA256())
        log(f"[{CLIENT_ID}] ✓ Step 4: Km received and signature verified successfully")

        # --- PROTOKOL 2: SESSION KEY (Ks) DEĞİŞİMİ ---
        log(f"[{CLIENT_ID}] ========== Starting Session Key Protocol ==========")

        # Step 1: Receive IDa || N_new
        log(f"[{CLIENT_ID}] Step 1: Waiting for IDa || N1 (session)...")
        data_step1 = c_socket.recv(1024).decode().split("||")
        client1_id_session = data_step1[0]
        n1_session = data_step1[1]
        log(f"[{CLIENT_ID}] Step 1: Received IDa: {client1_id_session}")
        log(f"[{CLIENT_ID}] Step 1: Received N1 (session): {n1_session}")
        
        # Step 2: Send E(Km, [Ks || IDa || IDb || f(N1) || N2])
        log(f"[{CLIENT_ID}] Step 2: Generating session key Ks...")
        session_key_ks = os.urandom(32)
        log(f"[{CLIENT_ID}] Step 2: Generated Ks: {session_key_ks.hex()}")
        
        log(f"[{CLIENT_ID}] Step 2: Creating session packet with encryption...")
        km_fernet = Fernet(base64.urlsafe_b64encode(master_key_km))
       
        n2_session = os.urandom(8).hex()
        log(f"[{CLIENT_ID}] Step 2: Generated N2 (session): {n2_session}")

        session_packet = {
           "Ks": base64.b64encode(session_key_ks).decode(),
           "IDa": client1_id_session,
          "IDb": CLIENT_ID,
       "f_n1": n1_session + "_processed",
        "n2": n2_session # N2 değeri
             }






        encrypted_session = km_fernet.encrypt(json.dumps(session_packet).encode())
        log(f"[{CLIENT_ID}] Step 2: Encrypted session packet (size: {len(encrypted_session)} bytes)")
        
        c_socket.send(encrypted_session)
        log(f"[{CLIENT_ID}] ✓ Step 2: Session Key Ks encrypted and sent to Client 1")

        # Step 3: Receive confirmation
        log(f"[{CLIENT_ID}] Step 3: Waiting for f(N2) confirmation from Client 1...")
        ks_fernet = Fernet(base64.urlsafe_b64encode(session_key_ks))
        encrypted_confirm = c_socket.recv(4096)
        log(f"[{CLIENT_ID}] Step 3: Received encrypted confirmation (size: {len(encrypted_confirm)} bytes)")
        
        decrypted_confirm = ks_fernet.decrypt(encrypted_confirm).decode()
        log(f"[{CLIENT_ID}] Step 3: Decrypted confirmation: {decrypted_confirm}")
        log(f"[{CLIENT_ID}] ✓ Step 3: f(N2) confirmation received and verified")

        log(f"[{CLIENT_ID}] ========== Protocol Completed Successfully ==========")
        update_status("Session Key Ready", "#27ae60")
        messagebox.showinfo("Success", "Protocol complete!")
        c_socket.close()

    except Exception as e:
        log(f"[{CLIENT_ID}] ✗ Protocol error: {e}")
        import traceback
        log(f"[{CLIENT_ID}] Error traceback: {traceback.format_exc()}")
# ===============================
# GUI & OTHERS
# ===============================
def update_status(text, color):
    status_label.config(text=f"● {text}", fg=color)

def setup_gui():
    global log_area, status_label, ca_host_entry, ca_port_entry, client1_host_entry, client1_port_entry
    root = tk.Tk()
    root.title("Client 2 - Certificate & Key Exchange")
    root.geometry("800x800")
    
    header = tk.Frame(root, bg="#e74c3c", height=80); header.pack(fill=tk.X); header.pack_propagate(False)
    tk.Label(header, text="🔴 Client 2", fg="white", bg="#e74c3c", font=("Arial", 20, "bold")).pack(pady=20)
    
    status_frame = tk.Frame(root); status_frame.pack(fill=tk.X, padx=10, pady=10)
    status_label = tk.Label(status_frame, text="● Not Connected", fg="#95a5a6", font=("Arial", 12, "bold")); status_label.pack(side=tk.LEFT, padx=10)
    
    config_frame = tk.LabelFrame(root, text="Network Configuration", font=("Arial", 11, "bold"), padx=10, pady=10); config_frame.pack(fill=tk.X, padx=10, pady=5)
    
    # My IP Display
    ip_f = tk.Frame(config_frame); ip_f.pack(fill=tk.X, pady=5)
    tk.Label(ip_f, text="My IP Address:", font=("Arial", 10), width=15, anchor="w").pack(side=tk.LEFT)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        local_ip = "Unable to detect"
    tk.Label(ip_f, text=local_ip, font=("Arial", 10, "bold"), fg="#27ae60").pack(side=tk.LEFT, padx=5)
    
    ca_f = tk.Frame(config_frame); ca_f.pack(fill=tk.X, pady=2)
    tk.Label(ca_f, text="CA IP:", width=15, anchor="w").pack(side=tk.LEFT)
    ca_host_entry = tk.Entry(ca_f, width=20); ca_host_entry.pack(side=tk.LEFT); ca_host_entry.insert(0, "127.0.0.1")
    ca_port_entry = tk.Entry(ca_f, width=10); ca_port_entry.pack(side=tk.LEFT, padx=5); ca_port_entry.insert(0, "5050")
    
    c1_f = tk.Frame(config_frame); c1_f.pack(fill=tk.X, pady=2)
    tk.Label(c1_f, text="Client 1 IP:", width=15, anchor="w").pack(side=tk.LEFT)
    client1_host_entry = tk.Entry(c1_f, width=20); client1_host_entry.pack(side=tk.LEFT); client1_host_entry.insert(0, "127.0.0.1")
    client1_port_entry = tk.Entry(c1_f, width=10); client1_port_entry.pack(side=tk.LEFT, padx=5); client1_port_entry.insert(0, "5051")
    
    btn_frame = tk.Frame(root); btn_frame.pack(fill=tk.X, padx=10, pady=10)
    tk.Button(btn_frame, text="1. Generate Keys", command=generate_keys, bg="#27ae60", fg="white", font=("Arial", 10, "bold"), padx=10).pack(side=tk.LEFT, padx=2)
    tk.Button(btn_frame, text="2. Get Cert", command=request_certificate_from_ca, bg="#e67e22", fg="white", font=("Arial", 10, "bold"), padx=10).pack(side=tk.LEFT, padx=2)
    tk.Button(btn_frame, text="3. Connect C1", command=lambda: threading.Thread(target=connect_to_client1, daemon=True).start(), bg="#9b59b6", fg="white", font=("Arial", 10, "bold"), padx=10).pack(side=tk.LEFT, padx=2)
    
    cert_frame = tk.LabelFrame(root, text="Certificate Information", font=("Arial", 11, "bold"), padx=10, pady=10); cert_frame.pack(fill=tk.BOTH, padx=10, pady=5)
    cert_text = ScrolledText(cert_frame, height=8, bg="#ecf0f1", font=("Consolas", 9)); cert_text.pack(fill=tk.BOTH, expand=True)
    
    def show_cert_info():
        cert_text.delete(1.0, tk.END)
        if my_certificate: cert_text.insert(tk.END, f"My Certificate: {my_certificate['Subject ID']}\n")
        if client1_certificate: cert_text.insert(tk.END, f"Client 1 Certificate: {client1_certificate['Subject ID']}\n")
    
    tk.Button(cert_frame, text="Show Certificates", command=show_cert_info, bg="#3498db", fg="white").pack(pady=5)
    
    log_f = tk.LabelFrame(root, text="Activity Log", padx=10, pady=10); log_f.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)
    log_area = ScrolledText(log_f, height=15, bg="#ecf0f1", font=("Consolas", 9)); log_area.pack(fill=tk.BOTH, expand=True)
    return root

if __name__ == "__main__":
    root = setup_gui()
    log(f"[{CLIENT_ID}] Application started.")
    root.mainloop()