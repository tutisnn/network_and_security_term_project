import socket
import json
import base64
import threading
import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# ===============================
# GLOBAL VARIABLES
# ===============================
ca_private_key = None
ca_public_key = None
log_area = None
cert_list = None
ca_port_entry = None
issued_certs = []
CA_PORT = 5050

# ===============================
# LOG FUNCTION (GUI + TERMINAL)
# ===============================
def log(message):
    timestamp = datetime.now().strftime("%H:%M:%S")
    formatted_msg = f"[{timestamp}] {message}"
    print(formatted_msg)
    if log_area:
        log_area.insert(tk.END, formatted_msg + "\n")
        log_area.see(tk.END)
        log_area.update()

# ===============================
# CA KEY GENERATION
# ===============================
def initialize_ca():
    global ca_private_key, ca_public_key
    log("[CA] Initializing Certificate Authority...")
    
    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    ca_public_key = ca_private_key.public_key()
    
    public_pem = ca_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    
    log("[CA] ✓ CA public/private keys generated successfully")
    log(f"[CA] CA Public Key Content:\n{public_pem}")

# ===============================
# CERTIFICATE CREATION
# ===============================
def create_certificate(subject_id, client_public_key_pem):
    subject_public_key_info = {
        "Algorithm ID": "RSA-2048",
        "Public Key Value": client_public_key_pem
    }
    
    validity_period = {
        "Not Before": str(datetime.now()),
        "Not After": str(datetime.now() + timedelta(days=365))
    }
    
    certificate = {
        "Version": "v3 (Oversimplified)", 
        "Serial Number": f"{len(issued_certs)+1:04d}", 
        "Issuer (CA) Name": "IZU Certificate Authority", 
        "Validity Period": validity_period, 
        "Subject ID": subject_id, 
        "Subject Public Key Info": subject_public_key_info 
    }
    
    certificate_bytes = json.dumps(certificate, sort_keys=True).encode()
    signature = ca_private_key.sign(
        certificate_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    certificate["CA Digital Signature"] = base64.b64encode(signature).decode()
    
    issued_certs.append({
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "subject": subject_id,
        "serial": certificate["Serial Number"]
    })
    
    return certificate

# ===============================
# HANDLE CLIENT CONNECTION
# ===============================
def handle_client(conn, addr):
    try:
        log(f"[CA] New connection from {addr[0]}:{addr[1]}")
        data = conn.recv(8192).decode()
        
        if not data:
            conn.close()
            return
        
        request = json.loads(data)
        subject_id = request.get("subject_id")
        client_public_key = request.get("public_key")
        
        log(f"[CA] Certificate request from: {subject_id}")
        
        certificate = create_certificate(subject_id, client_public_key)
        
        # Sertifika detaylarını logla
        readable_cert = json.dumps(certificate, indent=4, ensure_ascii=False)
        log(f"[CA] Full Certificate Content for {subject_id}:\n{readable_cert}")
        
        response = json.dumps(certificate)
        conn.send(response.encode())
        
        log(f"[CA] ✓ Certificate sent to {subject_id}")
        update_cert_list()
        
    except Exception as e:
        log(f"[CA] ✗ Error: {str(e)}")
    finally:
        conn.close()

# ===============================
# CA SERVER FUNCTION
# ===============================
def run_ca_server():
    global CA_PORT
    HOST = "0.0.0.0"
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, CA_PORT))
        server_socket.listen(5)
        
        log(f"[CA] ✓ Server listening on {HOST}:{CA_PORT}")
        
        while True:
            conn, addr = server_socket.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except Exception as e:
        log(f"[CA] ✗ Server error: {str(e)}")

# ===============================
# GUI FUNCTIONS
# ===============================
def update_cert_list():
    if cert_list:
        cert_list.delete(*cert_list.get_children())
        for cert in issued_certs:
            cert_list.insert("", tk.END, values=(cert["time"], cert["subject"], cert["serial"]))

def setup_gui():
    global log_area, cert_list, ca_port_entry
    
    root = tk.Tk()
    root.title("Certificate Authority (CA) - IZU")
    root.geometry("900x750")
    
    # Header
    header = tk.Frame(root, bg="#2c3e50", height=60)
    header.pack(fill=tk.X)
    tk.Label(header, text="🔐 IZU Certificate Authority", fg="white", bg="#2c3e50", font=("Arial", 16, "bold")).pack(pady=15)
    
    # Config
    config_frame = tk.LabelFrame(root, text="Server Configuration", padx=10, pady=10)
    config_frame.pack(fill=tk.X, padx=10, pady=5)
    
    # My IP Display
    ip_frame = tk.Frame(config_frame)
    ip_frame.pack(fill=tk.X, pady=5)
    tk.Label(ip_frame, text="My IP Address:", font=("Arial", 10), width=15, anchor="w").pack(side=tk.LEFT)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        local_ip = "Unable to detect"
    tk.Label(ip_frame, text=local_ip, font=("Arial", 10, "bold"), fg="#27ae60").pack(side=tk.LEFT, padx=5)
    
    # Port Config
    port_frame = tk.Frame(config_frame)
    port_frame.pack(fill=tk.X, pady=5)
    tk.Label(port_frame, text="Port:").pack(side=tk.LEFT)
    ca_port_entry = tk.Entry(port_frame, width=10)
    ca_port_entry.insert(0, "5050")
    ca_port_entry.pack(side=tk.LEFT, padx=5)
    
    def start_btn_cmd():
        global CA_PORT
        CA_PORT = int(ca_port_entry.get())
        ca_port_entry.config(state="disabled")
        start_btn.config(state="disabled")
        threading.Thread(target=run_ca_server, daemon=True).start()
    
    start_btn = tk.Button(port_frame, text="Start CA Server", command=start_btn_cmd, bg="#27ae60", fg="white", padx=10)
    start_btn.pack(side=tk.LEFT, padx=10)
    
    # Cert List
    list_frame = tk.LabelFrame(root, text="Issued Certificates", padx=10, pady=10)
    list_frame.pack(fill=tk.X, padx=10, pady=5)
    
    cols = ("Time", "Subject", "Serial")
    cert_list = ttk.Treeview(list_frame, columns=cols, show="headings", height=5)
    for col in cols: cert_list.heading(col, text=col)
    cert_list.pack(fill=tk.X)
    
    # Logs
    log_frame = tk.LabelFrame(root, text="System Logs", padx=10, pady=10)
    log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
    
    log_area = ScrolledText(log_frame, bg="#f8f9fa", font=("Consolas", 9))
    log_area.pack(fill=tk.BOTH, expand=True)
    
    return root

# ===============================
# MAIN
# ===============================
if __name__ == "__main__":
    # 1. Önce GUI'yi kur (log_area oluşsun)
    root = setup_gui()
    
    # 2. Sonra anahtarları üret (artık log_area'ya yazabilir)
    initialize_ca()
    
    log("[CA] System ready. Click 'Start CA Server' to begin listening.")
    
    root.mainloop()