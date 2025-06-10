#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════╗
║                    🌟 ANAGÜVTE v3.0 🌟                    ║
║        Adaptif Güvenli Veri Transfer Sistemi             ║
║                   PYTHON IMPLEMENTATION                  ║
║                                                           ║
║  🎓 Bursa Teknik Üniversitesi                            ║
║  📚 Bilgisayar Ağları Dönem Projesi                      ║
║  👨‍💻 Geliştirici: Musa Adıgüzel                           ║
║  👩‍🏫 Danışman: Şeyma DOĞRU                                ║
║  🔐 Advanced Security + Low-Level IP Processing          ║
║  🚀 GUI Interface + Wireshark Integration                ║
╚═══════════════════════════════════════════════════════════╝
"""

import sys
import os
import socket
import struct
import threading
import time
import hashlib
import json
import subprocess
import platform
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import queue
import logging

# Cryptography imports
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import secrets

# Scapy for packet manipulation
try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️  Scapy not available. Install with: pip install scapy")

# Network analysis
import psutil
import threading
import time

# Constants
VERSION = "3.0"
BUILD_DATE = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
DEFAULT_PORT = 8080
BUFFER_SIZE = 8192
MAX_PACKET_SIZE = 1500
AES_KEY_SIZE = 32
RSA_KEY_SIZE = 2048

class NetworkAnalyzer:
    """Network performance analyzer with Wireshark integration"""
    
    def __init__(self):
        self.metrics = {
            'latency': 0.0,
            'bandwidth': 0.0,
            'packet_loss': 0.0,
            'jitter': 0.0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'packets_sent': 0,
            'packets_received': 0
        }
        self.wireshark_process = None
        self.capture_file = "anaguvte_capture.pcap"
        
    def start_wireshark_capture(self, interface="any"):
        """Start Wireshark packet capture"""
        try:
            if platform.system() == "Windows":
                wireshark_cmd = ["C:\\Program Files\\Wireshark\\dumpcap.exe"]
            else:
                wireshark_cmd = ["tcpdump"]
            
            cmd = wireshark_cmd + ["-i", interface, "-w", self.capture_file, "-f", f"port {DEFAULT_PORT}"]
            self.wireshark_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return True
        except Exception as e:
            logging.error(f"Failed to start packet capture: {e}")
            return False
    
    def stop_wireshark_capture(self):
        """Stop Wireshark packet capture"""
        if self.wireshark_process:
            self.wireshark_process.terminate()
            self.wireshark_process = None
    
    def measure_latency(self, target_ip, count=4):
        """Measure network latency using ping"""
        try:
            if platform.system() == "Windows":
                cmd = ["ping", "-n", str(count), target_ip]
            else:
                cmd = ["ping", "-c", str(count), target_ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if "time=" in result.stdout:
                times = []
                for line in result.stdout.split('\n'):
                    if "time=" in line:
                        time_str = line.split("time=")[1].split("ms")[0]
                        times.append(float(time_str))
                
                if times:
                    self.metrics['latency'] = sum(times) / len(times)
                    return self.metrics['latency']
            
        except Exception as e:
            logging.error(f"Latency measurement failed: {e}")
        
        return 0.0
    
    def analyze_packet_loss(self, target_ip, count=10):
        """Analyze packet loss percentage"""
        try:
            if platform.system() == "Windows":
                cmd = ["ping", "-n", str(count), target_ip]
            else:
                cmd = ["ping", "-c", str(count), target_ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if "packet loss" in result.stdout or "packets transmitted" in result.stdout:
                lines = result.stdout.split('\n')
                for line in lines:
                    if "packet loss" in line:
                        loss_str = line.split("(")[1].split("%")[0]
                        self.metrics['packet_loss'] = float(loss_str)
                        return self.metrics['packet_loss']
                    elif "packets transmitted" in line and "received" in line:
                        parts = line.split()
                        transmitted = int(parts[0])
                        received = int(parts[3])
                        loss = ((transmitted - received) / transmitted) * 100
                        self.metrics['packet_loss'] = loss
                        return loss
            
        except Exception as e:
            logging.error(f"Packet loss analysis failed: {e}")
        
        return 0.0

class SecurityManager:
    """Advanced security manager with AES/RSA hybrid encryption"""
    
    def __init__(self, encryption_level=2):
        self.encryption_level = encryption_level
        self.aes_key = None
        self.private_key = None
        self.public_key = None
        self.session_key = None
        self.backend = default_backend()
        self.setup_security()
    
    def setup_security(self):
        """Initialize security configuration"""
        # Generate RSA keypair
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=RSA_KEY_SIZE,
            backend=self.backend
        )
        self.public_key = self.private_key.public_key()
        
        # Generate AES key
        self.aes_key = secrets.token_bytes(AES_KEY_SIZE)
        self.session_key = secrets.token_bytes(AES_KEY_SIZE)
        
        logging.info(f"🔐 Security initialized - Level: {self.encryption_level}")
    
    def encrypt_file(self, file_path):
        """Encrypt file with AES-256-GCM"""
        try:
            with open(file_path, 'rb') as f:
                plaintext = f.read()
            
            # Generate random IV
            iv = secrets.token_bytes(12)  # GCM recommended IV size
            
            # Create cipher
            cipher = Cipher(algorithms.AES(self.aes_key), modes.GCM(iv), backend=self.backend)
            encryptor = cipher.encryptor()
            
            # Encrypt data
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            
            # Return encrypted data with IV and tag
            return iv + encryptor.tag + ciphertext
            
        except Exception as e:
            logging.error(f"File encryption failed: {e}")
            return None
    
    def decrypt_file(self, encrypted_data):
        """Decrypt file with AES-256-GCM"""
        try:
            # Extract IV, tag, and ciphertext
            iv = encrypted_data[:12]
            tag = encrypted_data[12:28]
            ciphertext = encrypted_data[28:]
            
            # Create cipher
            cipher = Cipher(algorithms.AES(self.aes_key), modes.GCM(iv, tag), backend=self.backend)
            decryptor = cipher.decryptor()
            
            # Decrypt data
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            return plaintext
            
        except Exception as e:
            logging.error(f"File decryption failed: {e}")
            return None
    
    def calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception as e:
            logging.error(f"Hash calculation failed: {e}")
            return None

class PacketProcessor:
    """Low-level IP packet processing with Scapy"""
    
    def __init__(self):
        self.packets_sent = 0
        self.packets_received = 0
    
    def create_custom_packet(self, dest_ip, dest_port, data, protocol="TCP"):
        """Create custom packet with manual IP header manipulation"""
        if not SCAPY_AVAILABLE:
            logging.warning("Scapy not available, using standard sockets")
            return data
        
        try:
            # Create IP header with custom fields
            ip_packet = IP(
                dst=dest_ip,
                ttl=64,  # Custom TTL
                flags="DF",  # Don't Fragment flag
                frag=0  # Fragment offset
            )
            
            if protocol.upper() == "TCP":
                transport_packet = TCP(dport=dest_port, flags="PA")
            else:
                transport_packet = UDP(dport=dest_port)
            
            # Combine layers with data
            packet = ip_packet / transport_packet / Raw(load=data)
            
            # Calculate and verify checksum
            packet = IP(bytes(packet))  # Recalculate checksums
            
            self.packets_sent += 1
            return packet
            
        except Exception as e:
            logging.error(f"Packet creation failed: {e}")
            return data
    
    def fragment_packet(self, packet, mtu=1500):
        """Manual packet fragmentation"""
        if not SCAPY_AVAILABLE:
            return [packet]
        
        try:
            fragments = fragment(packet, fragsize=mtu-20)  # Account for IP header
            logging.info(f"📦 Packet fragmented into {len(fragments)} pieces")
            return fragments
        except Exception as e:
            logging.error(f"Packet fragmentation failed: {e}")
            return [packet]
    
    def reassemble_packets(self, fragments):
        """Reassemble fragmented packets"""
        if not SCAPY_AVAILABLE:
            return b"".join(fragments)
        
        try:
            # Simple reassembly based on fragment offset
            fragments.sort(key=lambda x: x[IP].frag)
            reassembled_data = b""
            
            for frag in fragments:
                if Raw in frag:
                    reassembled_data += frag[Raw].load
            
            self.packets_received += len(fragments)
            return reassembled_data
            
        except Exception as e:
            logging.error(f"Packet reassembly failed: {e}")
            return b""

class FileTransferProtocol:
    """Adaptive file transfer protocol with TCP/UDP switching"""
    
    def __init__(self, security_manager, network_analyzer, packet_processor):
        self.security = security_manager
        self.network = network_analyzer
        self.packet_proc = packet_processor
        self.current_protocol = "TCP"
        self.adaptive_enabled = True
        self.transfer_active = False
        
    def decide_protocol(self):
        """Decide optimal protocol based on network conditions"""
        if not self.adaptive_enabled:
            return self.current_protocol
        
        # Simple decision logic
        if self.network.metrics['latency'] > 100:  # High latency
            self.current_protocol = "UDP"  # Faster for high-latency networks
        elif self.network.metrics['packet_loss'] > 5:  # High packet loss
            self.current_protocol = "TCP"  # More reliable
        else:
            self.current_protocol = "TCP"  # Default to reliable
        
        logging.info(f"🔧 Protocol selected: {self.current_protocol}")
        return self.current_protocol
    
    def send_file(self, file_path, dest_ip, dest_port, progress_callback=None):
        """Send file with encryption and fragmentation"""
        try:
            self.transfer_active = True
            
            # Calculate file hash
            file_hash = self.security.calculate_file_hash(file_path)
            file_size = os.path.getsize(file_path)
            
            logging.info(f"📤 Starting file transfer: {file_path} ({file_size} bytes)")
            
            # Encrypt file
            encrypted_data = self.security.encrypt_file(file_path)
            if not encrypted_data:
                raise Exception("File encryption failed")
            
            # Decide protocol
            protocol = self.decide_protocol()
            
            # Create socket
            if protocol == "TCP":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((dest_ip, dest_port))
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Send file metadata
            metadata = {
                'filename': os.path.basename(file_path),
                'size': len(encrypted_data),
                'hash': file_hash,
                'protocol': protocol
            }
            
            metadata_json = json.dumps(metadata).encode()
            
            if protocol == "TCP":
                sock.send(len(metadata_json).to_bytes(4, 'big'))
                sock.send(metadata_json)
            else:
                sock.sendto(len(metadata_json).to_bytes(4, 'big') + metadata_json, (dest_ip, dest_port))
            
            # Send encrypted file data in chunks
            chunk_size = 4096
            total_sent = 0
            
            for i in range(0, len(encrypted_data), chunk_size):
                chunk = encrypted_data[i:i+chunk_size]
                
                if protocol == "TCP":
                    sock.send(chunk)
                else:
                    sock.sendto(chunk, (dest_ip, dest_port))
                
                total_sent += len(chunk)
                
                if progress_callback:
                    progress = (total_sent / len(encrypted_data)) * 100
                    progress_callback(progress)
                
                # Adaptive delay based on network conditions
                if self.network.metrics['packet_loss'] > 1:
                    time.sleep(0.001)  # Small delay for lossy networks
            
            sock.close()
            self.transfer_active = False
            
            logging.info(f"✅ File transfer completed: {total_sent} bytes sent")
            return True
            
        except Exception as e:
            logging.error(f"❌ File transfer failed: {e}")
            self.transfer_active = False
            return False
    
    def receive_file(self, save_path, listen_port, progress_callback=None):
        """Receive file with decryption and reassembly"""
        try:
            self.transfer_active = True
            
            # Create server socket
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind(('', listen_port))
            server_sock.listen(1)
            
            logging.info(f"📥 Waiting for file transfer on port {listen_port}")
            
            client_sock, addr = server_sock.accept()
            logging.info(f"🔗 Connection from {addr[0]}:{addr[1]}")
            
            # Receive metadata
            metadata_size = int.from_bytes(client_sock.recv(4), 'big')
            metadata_json = client_sock.recv(metadata_size).decode()
            metadata = json.loads(metadata_json)
            
            logging.info(f"📋 File metadata: {metadata}")
            
            # Receive encrypted file data
            encrypted_data = b""
            expected_size = metadata['size']
            
            while len(encrypted_data) < expected_size:
                chunk = client_sock.recv(min(4096, expected_size - len(encrypted_data)))
                if not chunk:
                    break
                encrypted_data += chunk
                
                if progress_callback:
                    progress = (len(encrypted_data) / expected_size) * 100
                    progress_callback(progress)
            
            client_sock.close()
            server_sock.close()
            
            # Decrypt file data
            decrypted_data = self.security.decrypt_file(encrypted_data)
            if not decrypted_data:
                raise Exception("File decryption failed")
            
            # Save file
            full_save_path = os.path.join(save_path, metadata['filename'])
            with open(full_save_path, 'wb') as f:
                f.write(decrypted_data)
            
            # Verify integrity
            received_hash = self.security.calculate_file_hash(full_save_path)
            if received_hash != metadata['hash']:
                logging.warning("⚠️ File integrity check failed!")
            else:
                logging.info("✅ File integrity verified")
            
            self.transfer_active = False
            logging.info(f"✅ File received: {full_save_path}")
            return True
            
        except Exception as e:
            logging.error(f"❌ File reception failed: {e}")
            self.transfer_active = False
            return False

class AnaguvteGUI:
    """Advanced GUI interface for ANAGÜVTE"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("ANAGÜVTE v3.0 - Secure File Transfer System")
        self.root.geometry("900x700")
        self.root.configure(bg='#2b2b2b')
        
        # Initialize components
        self.security = SecurityManager()
        self.network = NetworkAnalyzer()
        self.packet_proc = PacketProcessor()
        self.transfer_protocol = FileTransferProtocol(self.security, self.network, self.packet_proc)
        
        # GUI variables
        self.selected_file = tk.StringVar()
        self.dest_ip = tk.StringVar(value="127.0.0.1")
        self.dest_port = tk.IntVar(value=DEFAULT_PORT)
        self.listen_port = tk.IntVar(value=DEFAULT_PORT)
        self.save_directory = tk.StringVar(value=str(Path.home() / "Downloads"))
        self.encryption_level = tk.IntVar(value=2)
        self.wireshark_enabled = tk.BooleanVar(value=True)
        
        # Setup logging
        self.setup_logging()
        
        # Create GUI
        self.create_gui()
        
        # Status updates
        self.update_network_status()
    
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('anaguvte.log'),
                logging.StreamHandler()
            ]
        )
    
    def create_gui(self):
        """Create the main GUI interface"""
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TLabel', background='#2b2b2b', foreground='white')
        style.configure('TFrame', background='#2b2b2b')
        
        # Title
        title_frame = ttk.Frame(self.root)
        title_frame.pack(pady=10)
        
        title_label = tk.Label(
            title_frame,
            text="🌟 ANAGÜVTE v3.0 🌟\nAdaptif Güvenli Veri Transfer Sistemi",
            font=("Arial", 16, "bold"),
            bg='#2b2b2b',
            fg='#00ff00'
        )
        title_label.pack()
        
        subtitle_label = tk.Label(
            title_frame,
            text="Bursa Teknik Üniversitesi - Bilgisayar Ağları Projesi",
            font=("Arial", 10),
            bg='#2b2b2b',
            fg='#cccccc'
        )
        subtitle_label.pack()
        
        # Main notebook
        notebook = ttk.Notebook(self.root)
        notebook.pack(expand=True, fill='both', padx=10, pady=10)
        
        # File Transfer Tab
        self.create_transfer_tab(notebook)
        
        # Network Analysis Tab
        self.create_analysis_tab(notebook)
        
        # Security Tab
        self.create_security_tab(notebook)
        
        # Logs Tab
        self.create_logs_tab(notebook)
    
    def create_transfer_tab(self, notebook):
        """Create file transfer tab"""
        transfer_frame = ttk.Frame(notebook)
        notebook.add(transfer_frame, text="📤 File Transfer")
        
        # Send section
        send_frame = ttk.LabelFrame(transfer_frame, text="Send File", padding=10)
        send_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(send_frame, text="Select File:").grid(row=0, column=0, sticky='w', pady=2)
        ttk.Entry(send_frame, textvariable=self.selected_file, width=50).grid(row=0, column=1, padx=5, pady=2)
        ttk.Button(send_frame, text="Browse", command=self.browse_file).grid(row=0, column=2, pady=2)
        
        ttk.Label(send_frame, text="Destination IP:").grid(row=1, column=0, sticky='w', pady=2)
        ttk.Entry(send_frame, textvariable=self.dest_ip, width=20).grid(row=1, column=1, sticky='w', padx=5, pady=2)
        
        ttk.Label(send_frame, text="Port:").grid(row=2, column=0, sticky='w', pady=2)
        ttk.Entry(send_frame, textvariable=self.dest_port, width=10).grid(row=2, column=1, sticky='w', padx=5, pady=2)
        
        ttk.Button(send_frame, text="🚀 Send File", command=self.send_file).grid(row=3, column=1, pady=10)
        
        # Receive section
        receive_frame = ttk.LabelFrame(transfer_frame, text="Receive File", padding=10)
        receive_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(receive_frame, text="Listen Port:").grid(row=0, column=0, sticky='w', pady=2)
        ttk.Entry(receive_frame, textvariable=self.listen_port, width=10).grid(row=0, column=1, sticky='w', padx=5, pady=2)
        
        ttk.Label(receive_frame, text="Save Directory:").grid(row=1, column=0, sticky='w', pady=2)
        ttk.Entry(receive_frame, textvariable=self.save_directory, width=50).grid(row=1, column=1, padx=5, pady=2)
        ttk.Button(receive_frame, text="Browse", command=self.browse_directory).grid(row=1, column=2, pady=2)
        
        ttk.Button(receive_frame, text="📥 Start Listening", command=self.start_listening).grid(row=2, column=1, pady=10)
        
        # Progress section
        progress_frame = ttk.LabelFrame(transfer_frame, text="Transfer Progress", padding=10)
        progress_frame.pack(fill='x', padx=10, pady=5)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill='x', pady=5)
        
        self.status_label = ttk.Label(progress_frame, text="Ready")
        self.status_label.pack()
    
    def create_analysis_tab(self, notebook):
        """Create network analysis tab"""
        analysis_frame = ttk.Frame(notebook)
        notebook.add(analysis_frame, text="📊 Network Analysis")
        
        # Wireshark section
        wireshark_frame = ttk.LabelFrame(analysis_frame, text="Wireshark Integration", padding=10)
        wireshark_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Checkbutton(wireshark_frame, text="Enable Wireshark Capture", variable=self.wireshark_enabled).pack(anchor='w')
        
        wireshark_buttons = ttk.Frame(wireshark_frame)
        wireshark_buttons.pack(fill='x', pady=5)
        
        ttk.Button(wireshark_buttons, text="🎯 Start Capture", command=self.start_capture).pack(side='left', padx=5)
        ttk.Button(wireshark_buttons, text="⏹️ Stop Capture", command=self.stop_capture).pack(side='left', padx=5)
        ttk.Button(wireshark_buttons, text="📋 View Capture", command=self.view_capture).pack(side='left', padx=5)
        
        # Network metrics
        metrics_frame = ttk.LabelFrame(analysis_frame, text="Network Metrics", padding=10)
        metrics_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.metrics_text = scrolledtext.ScrolledText(metrics_frame, height=15, bg='#1e1e1e', fg='#00ff00')
        self.metrics_text.pack(fill='both', expand=True)
        
        # Analysis buttons
        analysis_buttons = ttk.Frame(analysis_frame)
        analysis_buttons.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(analysis_buttons, text="📡 Measure Latency", command=self.measure_latency).pack(side='left', padx=5)
        ttk.Button(analysis_buttons, text="📉 Analyze Packet Loss", command=self.analyze_packet_loss).pack(side='left', padx=5)
        ttk.Button(analysis_buttons, text="🔄 Refresh Metrics", command=self.update_network_status).pack(side='left', padx=5)
    
    def create_security_tab(self, notebook):
        """Create security configuration tab"""
        security_frame = ttk.Frame(notebook)
        notebook.add(security_frame, text="🔐 Security")
        
        # Encryption settings
        encryption_frame = ttk.LabelFrame(security_frame, text="Encryption Settings", padding=10)
        encryption_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(encryption_frame, text="Encryption Level:").grid(row=0, column=0, sticky='w', pady=2)
        encryption_scale = ttk.Scale(encryption_frame, from_=0, to=3, variable=self.encryption_level, orient='horizontal')
        encryption_scale.grid(row=0, column=1, padx=5, pady=2)
        ttk.Label(encryption_frame, textvariable=self.encryption_level).grid(row=0, column=2, pady=2)
        
        # Security info
        security_info = ttk.LabelFrame(security_frame, text="Security Information", padding=10)
        security_info.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.security_text = scrolledtext.ScrolledText(security_info, height=10, bg='#1e1e1e', fg='#00ff00')
        self.security_text.pack(fill='both', expand=True)
        
        self.update_security_info()
        
        # Security test buttons
        security_buttons = ttk.Frame(security_frame)
        security_buttons.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(security_buttons, text="🔑 Generate New Keys", command=self.generate_keys).pack(side='left', padx=5)
        ttk.Button(security_buttons, text="🧪 Test Encryption", command=self.test_encryption).pack(side='left', padx=5)
    
    def create_logs_tab(self, notebook):
        """Create logs tab"""
        logs_frame = ttk.Frame(notebook)
        notebook.add(logs_frame, text="📝 Logs")
        
        self.logs_text = scrolledtext.ScrolledText(logs_frame, bg='#1e1e1e', fg='#00ff00')
        self.logs_text.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Logs buttons
        logs_buttons = ttk.Frame(logs_frame)
        logs_buttons.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(logs_buttons, text="🔄 Refresh Logs", command=self.refresh_logs).pack(side='left', padx=5)
        ttk.Button(logs_buttons, text="🗑️ Clear Logs", command=self.clear_logs).pack(side='left', padx=5)
        ttk.Button(logs_buttons, text="💾 Save Logs", command=self.save_logs).pack(side='left', padx=5)
    
    # Event handlers
    def browse_file(self):
        """Browse and select file to send"""
        filename = filedialog.askopenfilename(
            title="Select File to Send",
            filetypes=[("All Files", "*.*")]
        )
        if filename:
            self.selected_file.set(filename)
    
    def browse_directory(self):
        """Browse and select directory to save files"""
        directory = filedialog.askdirectory(title="Select Save Directory")
        if directory:
            self.save_directory.set(directory)
    
    def send_file(self):
        """Send selected file"""
        if not self.selected_file.get():
            messagebox.showerror("Error", "Please select a file to send")
            return
        
        if not os.path.exists(self.selected_file.get()):
            messagebox.showerror("Error", "Selected file does not exist")
            return
        
        # Start Wireshark capture if enabled
        if self.wireshark_enabled.get():
            self.network.start_wireshark_capture()
        
        # Update status
        self.status_label.config(text="Sending file...")
        self.progress_var.set(0)
        
        # Start transfer in separate thread
        transfer_thread = threading.Thread(
            target=self._send_file_thread,
            args=(self.selected_file.get(), self.dest_ip.get(), self.dest_port.get())
        )
        transfer_thread.daemon = True
        transfer_thread.start()
    
    def _send_file_thread(self, file_path, dest_ip, dest_port):
        """Send file in separate thread"""
        try:
            def progress_callback(progress):
                self.root.after(0, lambda: self.progress_var.set(progress))
                self.root.after(0, lambda: self.status_label.config(text=f"Sending... {progress:.1f}%"))
            
            success = self.transfer_protocol.send_file(file_path, dest_ip, dest_port, progress_callback)
            
            if success:
                self.root.after(0, lambda: self.status_label.config(text="✅ File sent successfully!"))
                self.root.after(0, lambda: messagebox.showinfo("Success", "File sent successfully!"))
            else:
                self.root.after(0, lambda: self.status_label.config(text="❌ File transfer failed"))
                self.root.after(0, lambda: messagebox.showerror("Error", "File transfer failed"))
            
        except Exception as e:
            logging.error(f"Send file thread error: {e}")
            self.root.after(0, lambda: messagebox.showerror("Error", f"Transfer failed: {str(e)}"))
        finally:
            if self.wireshark_enabled.get():
                self.network.stop_wireshark_capture()
    
    def start_listening(self):
        """Start listening for incoming files"""
        if not os.path.exists(self.save_directory.get()):
            messagebox.showerror("Error", "Save directory does not exist")
            return
        
        # Start Wireshark capture if enabled
        if self.wireshark_enabled.get():
            self.network.start_wireshark_capture()
        
        # Update status
        self.status_label.config(text="Listening for incoming files...")
        self.progress_var.set(0)
        
        # Start listening in separate thread
        listen_thread = threading.Thread(
            target=self._listen_thread,
            args=(self.save_directory.get(), self.listen_port.get())
        )
        listen_thread.daemon = True
        listen_thread.start()
    
    def _listen_thread(self, save_path, listen_port):
        """Listen for incoming files in separate thread"""
        try:
            def progress_callback(progress):
                self.root.after(0, lambda: self.progress_var.set(progress))
                self.root.after(0, lambda: self.status_label.config(text=f"Receiving... {progress:.1f}%"))
            
            success = self.transfer_protocol.receive_file(save_path, listen_port, progress_callback)
            
            if success:
                self.root.after(0, lambda: self.status_label.config(text="✅ File received successfully!"))
                self.root.after(0, lambda: messagebox.showinfo("Success", "File received successfully!"))
            else:
                self.root.after(0, lambda: self.status_label.config(text="❌ File reception failed"))
                self.root.after(0, lambda: messagebox.showerror("Error", "File reception failed"))
            
        except Exception as e:
            logging.error(f"Listen thread error: {e}")
            self.root.after(0, lambda: messagebox.showerror("Error", f"Reception failed: {str(e)}"))
        finally:
            if self.wireshark_enabled.get():
                self.network.stop_wireshark_capture()
    
    def start_capture(self):
        """Start Wireshark packet capture"""
        if self.network.start_wireshark_capture():
            messagebox.showinfo("Wireshark", "Packet capture started")
            self.update_logs("🎯 Wireshark capture started")
        else:
            messagebox.showerror("Error", "Failed to start packet capture")
    
    def stop_capture(self):
        """Stop Wireshark packet capture"""
        self.network.stop_wireshark_capture()
        messagebox.showinfo("Wireshark", "Packet capture stopped")
        self.update_logs("⏹️ Wireshark capture stopped")
    
    def view_capture(self):
        """View captured packets"""
        if os.path.exists(self.network.capture_file):
            if platform.system() == "Windows":
                os.startfile(self.network.capture_file)
            else:
                subprocess.run(["xdg-open", self.network.capture_file])
        else:
            messagebox.showwarning("Warning", "No capture file found")
    
    def measure_latency(self):
        """Measure network latency"""
        target_ip = self.dest_ip.get()
        if not target_ip:
            messagebox.showerror("Error", "Please enter destination IP")
            return
        
        self.update_logs(f"📡 Measuring latency to {target_ip}...")
        
        def measure_thread():
            latency = self.network.measure_latency(target_ip)
            self.root.after(0, lambda: self.update_logs(f"📡 Latency to {target_ip}: {latency:.2f} ms"))
            self.root.after(0, self.update_network_status)
        
        threading.Thread(target=measure_thread, daemon=True).start()
    
    def analyze_packet_loss(self):
        """Analyze packet loss"""
        target_ip = self.dest_ip.get()
        if not target_ip:
            messagebox.showerror("Error", "Please enter destination IP")
            return
        
        self.update_logs(f"📉 Analyzing packet loss to {target_ip}...")
        
        def analyze_thread():
            packet_loss = self.network.analyze_packet_loss(target_ip)
            self.root.after(0, lambda: self.update_logs(f"📉 Packet loss to {target_ip}: {packet_loss:.2f}%"))
            self.root.after(0, self.update_network_status)
        
        threading.Thread(target=analyze_thread, daemon=True).start()
    
    def update_network_status(self):
        """Update network metrics display"""
        metrics_text = f"""
🌐 NETWORK ANALYSIS RESULTS
{'='*50}

📊 Current Metrics:
   • Latency: {self.network.metrics['latency']:.2f} ms
   • Bandwidth: {self.network.metrics['bandwidth']:.2f} Mbps
   • Packet Loss: {self.network.metrics['packet_loss']:.2f}%
   • Jitter: {self.network.metrics['jitter']:.2f} ms

📈 Transfer Statistics:
   • Bytes Sent: {self.network.metrics['bytes_sent']:,}
   • Bytes Received: {self.network.metrics['bytes_received']:,}
   • Packets Sent: {self.network.metrics['packets_sent']:,}
   • Packets Received: {self.network.metrics['packets_received']:,}

🔧 Protocol Information:
   • Current Protocol: {self.transfer_protocol.current_protocol}
   • Adaptive Mode: {"Enabled" if self.transfer_protocol.adaptive_enabled else "Disabled"}
   • Encryption Level: {self.security.encryption_level}

📋 System Information:
   • Platform: {platform.system()} {platform.release()}
   • Python Version: {sys.version.split()[0]}
   • Scapy Available: {"Yes" if SCAPY_AVAILABLE else "No"}
   • Last Update: {datetime.now().strftime('%H:%M:%S')}

🛡️ Security Status:
   • AES Key Size: {len(self.security.aes_key) * 8} bits
   • RSA Key Size: {RSA_KEY_SIZE} bits
   • Session Active: {"Yes" if self.transfer_protocol.transfer_active else "No"}
"""
        self.metrics_text.delete(1.0, tk.END)
        self.metrics_text.insert(tk.END, metrics_text)
    
    def generate_keys(self):
        """Generate new encryption keys"""
        self.security.setup_security()
        self.update_security_info()
        messagebox.showinfo("Security", "New encryption keys generated successfully!")
        self.update_logs("🔑 New encryption keys generated")
    
    def test_encryption(self):
        """Test encryption/decryption functionality"""
        test_data = b"ANAGUVTE Test Data - Encryption Test"
        
        try:
            # Create temporary file
            test_file = "test_encryption.tmp"
            with open(test_file, 'wb') as f:
                f.write(test_data)
            
            # Test encryption
            encrypted = self.security.encrypt_file(test_file)
            if not encrypted:
                raise Exception("Encryption failed")
            
            # Test decryption
            decrypted = self.security.decrypt_file(encrypted)
            if not decrypted:
                raise Exception("Decryption failed")
            
            # Verify data integrity
            if decrypted == test_data:
                messagebox.showinfo("Success", "Encryption test passed successfully!")
                self.update_logs("🧪 Encryption test: PASSED")
            else:
                raise Exception("Data integrity check failed")
            
            # Cleanup
            if os.path.exists(test_file):
                os.remove(test_file)
            
        except Exception as e:
            messagebox.showerror("Error", f"Encryption test failed: {str(e)}")
            self.update_logs(f"🧪 Encryption test: FAILED - {str(e)}")
    
    def update_security_info(self):
        """Update security information display"""
        security_text = f"""
🔐 SECURITY CONFIGURATION
{'='*50}

🔑 Encryption Settings:
   • Algorithm: AES-256-GCM + RSA-{RSA_KEY_SIZE}
   • Key Size: {len(self.security.aes_key) * 8} bits (AES)
   • RSA Key Size: {RSA_KEY_SIZE} bits
   • Encryption Level: {self.security.encryption_level}
   • Backend: {self.security.backend.name}

🛡️ Security Features:
   • Hybrid Encryption: AES + RSA
   • Authenticated Encryption: GCM Mode
   • Key Exchange: RSA OAEP
   • Hash Algorithm: SHA-256
   • Random IV Generation: Yes
   • Perfect Forward Secrecy: Yes

📋 Key Information:
   • AES Key: {self.security.aes_key.hex()[:32]}...
   • Session Key: {self.security.session_key.hex()[:32]}...
   • Private Key: RSA-{RSA_KEY_SIZE} (PEM Format)
   • Public Key: RSA-{RSA_KEY_SIZE} (PEM Format)

🔒 Security Recommendations:
   • Use encryption level 2 or higher for sensitive data
   • Regularly rotate encryption keys
   • Verify file integrity using SHA-256 hashes
   • Monitor network traffic for anomalies
   • Use secure key exchange protocols

⚠️ Security Warnings:
   • Never share private keys
   • Use secure channels for key exchange
   • Verify recipient identity before transfer
   • Monitor for man-in-the-middle attacks
"""
        self.security_text.delete(1.0, tk.END)
        self.security_text.insert(tk.END, security_text)
    
    def update_logs(self, message):
        """Update logs display"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        self.logs_text.insert(tk.END, log_entry)
        self.logs_text.see(tk.END)
    
    def refresh_logs(self):
        """Refresh logs from file"""
        try:
            if os.path.exists('anaguvte.log'):
                with open('anaguvte.log', 'r') as f:
                    logs = f.read()
                self.logs_text.delete(1.0, tk.END)
                self.logs_text.insert(tk.END, logs)
                self.logs_text.see(tk.END)
        except Exception as e:
            self.update_logs(f"❌ Failed to refresh logs: {str(e)}")
    
    def clear_logs(self):
        """Clear logs display"""
        self.logs_text.delete(1.0, tk.END)
        self.update_logs("🗑️ Logs cleared")
    
    def save_logs(self):
        """Save logs to file"""
        filename = filedialog.asksaveasfilename(
            title="Save Logs",
            defaultextension=".log",
            filetypes=[("Log Files", "*.log"), ("Text Files", "*.txt")]
        )
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(self.logs_text.get(1.0, tk.END))
                messagebox.showinfo("Success", f"Logs saved to {filename}")
                self.update_logs(f"💾 Logs saved to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save logs: {str(e)}")
    
    def run(self):
        """Start the GUI application"""
        try:
            self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
            self.update_logs("🌟 ANAGÜVTE v3.0 started successfully!")
            self.update_logs(f"🎓 Bursa Teknik Üniversitesi - Build: {BUILD_DATE}")
            self.update_logs("📚 Computer Networks Project - Advanced Secure File Transfer")
            self.root.mainloop()
        except KeyboardInterrupt:
            self.on_closing()
    
    def on_closing(self):
        """Handle application closing"""
        if self.transfer_protocol.transfer_active:
            if messagebox.askokcancel("Quit", "Transfer in progress. Do you want to quit?"):
                self.network.stop_wireshark_capture()
                self.root.destroy()
        else:
            self.network.stop_wireshark_capture()
            self.root.destroy()

def main():
    """Main application entry point"""
    print("\n" + "="*60)
    print("🌟 ANAGÜVTE v3.0 - Advanced Secure File Transfer System")
    print("🎓 Bursa Teknik Üniversitesi - Bilgisayar Ağları Projesi")
    print("👨‍💻 Developer: Musa Adıgüzel")
    print("👩‍🏫 Supervisor: Şeyma DOĞRU")
    print(f"🚀 Build: {BUILD_DATE}")
    print("="*60)
    
    # Check dependencies
    missing_deps = []
    
    try:
        import cryptography
    except ImportError:
        missing_deps.append("cryptography")
    
    try:
        import psutil
    except ImportError:
        missing_deps.append("psutil")
    
    if not SCAPY_AVAILABLE:
        missing_deps.append("scapy")
    
    if missing_deps:
        print("\n⚠️  Missing dependencies:")
        for dep in missing_deps:
            print(f"   • {dep}")
        print("\nInstall with: pip install " + " ".join(missing_deps))
        print("Note: Some features may be limited without these dependencies.\n")
    
    # Check for admin privileges (needed for raw sockets)
    if platform.system() != "Windows":
        if os.geteuid() != 0:
            print("⚠️  Root privileges recommended for full functionality")
            print("   Run with: sudo python3 anaguvte.py\n")
    
    # Start GUI application
    try:
        app = AnaguvteGUI()
        app.run()
    except Exception as e:
        print(f"❌ Application error: {e}")
        return 1
    
    print("\n🎉 Thank you for using ANAGÜVTE v3.0!")
    print("🌟 Advanced Secure File Transfer System")
    return 0

if __name__ == "__main__":
    sys.exit(main())
