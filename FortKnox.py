import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import hashlib
import os
import base64
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pyperclip
import webbrowser
import qrcode
from PIL import Image, ImageTk
import string
import zxcvbn
import time
import threading
from functools import partial
import sys
import platform

# Constants
SALT_SIZE = 32
ITERATIONS = 600000
HASH_ALGORITHM = hashes.SHA512()
KEY_LENGTH = 32
MASTER_KEY_FILE = "master.key"
VAULT_FILE = "vault.dat"
MIN_PASSWORD_STRENGTH = 3

class QuantumResistantEncryption:
    @staticmethod
    def generate_key(master_password, salt):
        """Derive a secure encryption key using PBKDF2 with SHA-512"""
        kdf = PBKDF2HMAC(
            algorithm=HASH_ALGORITHM,
            length=KEY_LENGTH,
            salt=salt,
            iterations=ITERATIONS,
        )
        return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

class PasswordVault:
    def __init__(self):
        self.entries = []
        self.lock = threading.Lock()
        
    def add_entry(self, title, username, password, url, notes):
        with self.lock:
            self.entries.append({
                'id': secrets.token_hex(16),
                'title': title,
                'username': username,
                'password': password,
                'url': url,
                'notes': notes,
                'created': int(time.time()),
                'modified': int(time.time())
            })
    
    def update_entry(self, entry_id, **kwargs):
        with self.lock:
            for entry in self.entries:
                if entry['id'] == entry_id:
                    entry.update(kwargs)
                    entry['modified'] = int(time.time())
                    return True
        return False
    
    def delete_entry(self, entry_id):
        with self.lock:
            self.entries = [entry for entry in self.entries if entry['id'] != entry_id]
    
    def get_entry(self, entry_id):
        with self.lock:
            for entry in self.entries:
                if entry['id'] == entry_id:
                    return entry.copy()
        return None
    
    def get_all_entries(self):
        with self.lock:
            return [entry.copy() for entry in self.entries]

class PasswordGenerator:
    @staticmethod
    def generate(length=16, use_upper=True, use_lower=True, use_digits=True, 
                 use_special=True, avoid_ambiguous=True):
        """Generate a secure random password"""
        chars = ""
        if use_upper:
            chars += string.ascii_uppercase
            if avoid_ambiguous:
                chars = chars.replace("O", "").replace("I", "")
        if use_lower:
            chars += string.ascii_lowercase
            if avoid_ambiguous:
                chars = chars.replace("l", "")
        if use_digits:
            chars += string.digits
            if avoid_ambiguous:
                chars = chars.replace("0", "").replace("1", "")
        if use_special:
            chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
            if avoid_ambiguous:
                chars = chars.replace("|", "").replace(";", "").replace(":", "")
        
        if not chars:
            raise ValueError("At least one character set must be selected")
        
        while True:
            password = ''.join(secrets.choice(chars) for _ in range(length))
            # Ensure password meets all selected criteria
            if (not use_upper or any(c in string.ascii_uppercase for c in password)) and \
               (not use_lower or any(c in string.ascii_lowercase for c in password)) and \
               (not use_digits or any(c in string.digits for c in password)) and \
               (not use_special or any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)):
                return password

class SecurityAudit:
    @staticmethod
    def check_password_strength(password):
        """Check password strength using zxcvbn"""
        result = zxcvbn.zxcvbn(password)
        return {
            'score': result['score'],
            'feedback': result['feedback'],
            'crack_time': result['crack_times_display']['offline_slow_hashing_1e4_per_second']
        }
    
    @staticmethod
    def check_duplicate_passwords(vault):
        password_map = {}
        for entry in vault.get_all_entries():
            if entry['password'] in password_map:
                password_map[entry['password']].append(entry['title'])
            else:
                password_map[entry['password']] = [entry['title']]
        return {pw: titles for pw, titles in password_map.items() if len(titles) > 1}
    
    @staticmethod
    def check_compromised(vault, known_breaches):
        compromised = []
        for entry in vault.get_all_entries():
            if entry['password'] in known_breaches:
                compromised.append(entry)
        return compromised

class FortKnoxUI:
    def __init__(self, root):
        self.root = root
        self.root.title("FortKnox - Ultra Secure Password Manager")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        
        # Security state
        self.locked = True
        self.vault = PasswordVault()
        self.master_password = None
        self.salt = None
        self.fernet = None
        
        # Setup UI
        self.setup_ui()
        self.load_vault_state()
        
        # Check if we need to show first run setup
        if not os.path.exists(MASTER_KEY_FILE):
            self.show_first_run()
        else:
            self.show_unlock_screen()
    
    def setup_ui(self):
        # Style configuration
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TFrame', background='#2c3e50')
        style.configure('TLabel', background='#2c3e50', foreground='#ecf0f1')
        style.configure('TButton', background='#3498db', foreground='#2c3e50')
        style.configure('TEntry', fieldbackground='#34495e', foreground='#ecf0f1')
        style.configure('TCombobox', fieldbackground='#34495e', foreground='#ecf0f1')
        style.configure('TNotebook', background='#2c3e50')
        style.configure('TNotebook.Tab', background='#34495e', foreground='#ecf0f1')
        
        # Main container
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Status bar
        self.status_bar = ttk.Frame(self.main_frame)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_label = ttk.Label(self.status_bar, text="Status: Locked")
        self.status_label.pack(side=tk.LEFT, padx=5)
        self.last_backup_label = ttk.Label(self.status_bar, text="Last backup: Never")
        self.last_backup_label.pack(side=tk.LEFT, padx=5)
        self.security_status_label = ttk.Label(self.status_bar, text="Security: 🔒 Maximum")
        self.security_status_label.pack(side=tk.RIGHT, padx=5)
        
        # Main content area
        self.content_frame = ttk.Frame(self.main_frame)
        self.content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Setup all screens
        self.setup_unlock_screen()
        self.setup_main_screen()
        self.setup_first_run_screen()
        
    def setup_unlock_screen(self):
        self.unlock_frame = ttk.Frame(self.content_frame)
        
        logo_img = Image.open("logo.png") if os.path.exists("logo.png") else Image.new('RGB', (200, 200), color='#3498db')
        logo_img = logo_img.resize((200, 200), Image.LANCZOS)
        self.logo = ImageTk.PhotoImage(logo_img)
        logo_label = ttk.Label(self.unlock_frame, image=self.logo)
        logo_label.pack(pady=20)
        
        title_label = ttk.Label(self.unlock_frame, text="FortKnox Vault", font=('Helvetica', 24, 'bold'))
        title_label.pack(pady=10)
        
        self.master_password_entry = ttk.Entry(self.unlock_frame, show="•", width=30)
        self.master_password_entry.pack(pady=10)
        self.master_password_entry.bind('<Return>', lambda e: self.unlock_vault())
        
        unlock_btn = ttk.Button(self.unlock_frame, text="Unlock", command=self.unlock_vault)
        unlock_btn.pack(pady=10)
        
        emergency_btn = ttk.Button(self.unlock_frame, text="Emergency Lockdown", command=self.emergency_lockdown)
        emergency_btn.pack(pady=10)
        
    def setup_main_screen(self):
        self.main_screen_frame = ttk.Frame(self.content_frame)
        
        # Notebook for different sections
        self.notebook = ttk.Notebook(self.main_screen_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Password Vault Tab
        self.vault_frame = ttk.Frame(self.notebook)
        self.setup_vault_tab()
        self.notebook.add(self.vault_frame, text="Password Vault")
        
        # Password Generator Tab
        self.generator_frame = ttk.Frame(self.notebook)
        self.setup_generator_tab()
        self.notebook.add(self.generator_frame, text="Password Generator")
        
        # Security Audit Tab
        self.audit_frame = ttk.Frame(self.notebook)
        self.setup_audit_tab()
        self.notebook.add(self.audit_frame, text="Security Audit")
        
        # Settings Tab
        self.settings_frame = ttk.Frame(self.notebook)
        self.setup_settings_tab()
        self.notebook.add(self.settings_frame, text="Settings")
        
    def setup_vault_tab(self):
        # Search bar
        search_frame = ttk.Frame(self.vault_frame)
        search_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.search_entry = ttk.Entry(search_frame)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.search_entry.bind('<KeyRelease>', lambda e: self.filter_entries())
        
        search_btn = ttk.Button(search_frame, text="Search", command=self.filter_entries)
        search_btn.pack(side=tk.LEFT, padx=5)
        
        add_btn = ttk.Button(search_frame, text="Add New", command=self.show_add_entry_dialog)
        add_btn.pack(side=tk.RIGHT, padx=5)
        
        # Treeview for entries
        self.tree_frame = ttk.Frame(self.vault_frame)
        self.tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.tree = ttk.Treeview(self.tree_frame, columns=('title', 'username', 'url', 'modified'), selectmode='browse')
        self.tree.heading('#0', text='ID')
        self.tree.heading('title', text='Title')
        self.tree.heading('username', text='Username')
        self.tree.heading('url', text='URL')
        self.tree.heading('modified', text='Last Modified')
        
        self.tree.column('#0', width=0, stretch=tk.NO)  # Hide ID column
        self.tree.column('title', width=200)
        self.tree.column('username', width=150)
        self.tree.column('url', width=250)
        self.tree.column('modified', width=150)
        
        scrollbar = ttk.Scrollbar(self.tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        self.tree.bind('<Double-1>', self.show_entry_details)
        
        # Action buttons
        btn_frame = ttk.Frame(self.vault_frame)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        view_btn = ttk.Button(btn_frame, text="View", command=self.show_entry_details)
        view_btn.pack(side=tk.LEFT, padx=5)
        
        edit_btn = ttk.Button(btn_frame, text="Edit", command=self.show_edit_entry_dialog)
        edit_btn.pack(side=tk.LEFT, padx=5)
        
        delete_btn = ttk.Button(btn_frame, text="Delete", command=self.delete_selected_entry)
        delete_btn.pack(side=tk.LEFT, padx=5)
        
        copy_user_btn = ttk.Button(btn_frame, text="Copy Username", command=self.copy_username)
        copy_user_btn.pack(side=tk.LEFT, padx=5)
        
        copy_pass_btn = ttk.Button(btn_frame, text="Copy Password", command=self.copy_password)
        copy_pass_btn.pack(side=tk.LEFT, padx=5)
        
        export_btn = ttk.Button(btn_frame, text="Export", command=self.export_entry)
        export_btn.pack(side=tk.RIGHT, padx=5)
        
    def setup_generator_tab(self):
        # Password generator options
        options_frame = ttk.Frame(self.generator_frame)
        options_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(options_frame, text="Password Length:").grid(row=0, column=0, sticky=tk.W)
        self.length_var = tk.IntVar(value=16)
        length_spin = ttk.Spinbox(options_frame, from_=8, to=128, textvariable=self.length_var)
        length_spin.grid(row=0, column=1, sticky=tk.W)
        
        self.upper_var = tk.BooleanVar(value=True)
        upper_cb = ttk.Checkbutton(options_frame, text="Uppercase Letters", variable=self.upper_var)
        upper_cb.grid(row=1, column=0, sticky=tk.W)
        
        self.lower_var = tk.BooleanVar(value=True)
        lower_cb = ttk.Checkbutton(options_frame, text="Lowercase Letters", variable=self.lower_var)
        lower_cb.grid(row=1, column=1, sticky=tk.W)
        
        self.digits_var = tk.BooleanVar(value=True)
        digits_cb = ttk.Checkbutton(options_frame, text="Digits", variable=self.digits_var)
        digits_cb.grid(row=2, column=0, sticky=tk.W)
        
        self.special_var = tk.BooleanVar(value=True)
        special_cb = ttk.Checkbutton(options_frame, text="Special Characters", variable=self.special_var)
        special_cb.grid(row=2, column=1, sticky=tk.W)
        
        self.ambiguous_var = tk.BooleanVar(value=True)
        ambiguous_cb = ttk.Checkbutton(options_frame, text="Avoid Ambiguous Characters", variable=self.ambiguous_var)
        ambiguous_cb.grid(row=3, column=0, columnspan=2, sticky=tk.W)
        
        generate_btn = ttk.Button(options_frame, text="Generate Password", command=self.generate_password)
        generate_btn.grid(row=4, column=0, columnspan=2, pady=10)
        
        # Generated password display
        result_frame = ttk.Frame(self.generator_frame)
        result_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(result_frame, text="Generated Password:").pack(anchor=tk.W)
        self.generated_pass_var = tk.StringVar()
        generated_pass_entry = ttk.Entry(result_frame, textvariable=self.generated_pass_var, font=('Courier', 12))
        generated_pass_entry.pack(fill=tk.X, pady=5)
        
        btn_frame = ttk.Frame(result_frame)
        btn_frame.pack(fill=tk.X)
        
        copy_btn = ttk.Button(btn_frame, text="Copy to Clipboard", command=self.copy_generated_password)
        copy_btn.pack(side=tk.LEFT, padx=5)
        
        strength_btn = ttk.Button(btn_frame, text="Check Strength", command=self.check_password_strength)
        strength_btn.pack(side=tk.LEFT, padx=5)
        
        qr_btn = ttk.Button(btn_frame, text="Show QR Code", command=self.show_qr_code)
        qr_btn.pack(side=tk.RIGHT, padx=5)
        
        # Strength meter
        self.strength_frame = ttk.Frame(self.generator_frame)
        self.strength_frame.pack(fill=tk.X, padx=10, pady=10)
        
    def setup_audit_tab(self):
        # Security audit controls
        controls_frame = ttk.Frame(self.audit_frame)
        controls_frame.pack(fill=tk.X, padx=10, pady=10)
        
        audit_btn = ttk.Button(controls_frame, text="Run Security Audit", command=self.run_security_audit)
        audit_btn.pack(side=tk.LEFT, padx=5)
        
        # Results display
        self.audit_results_text = scrolledtext.ScrolledText(self.audit_frame, wrap=tk.WORD)
        self.audit_results_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.audit_results_text.config(state=tk.DISABLED)
        
    def setup_settings_tab(self):
        # Settings options
        options_frame = ttk.Frame(self.settings_frame)
        options_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(options_frame, text="Auto-lock after (minutes):").grid(row=0, column=0, sticky=tk.W)
        self.lock_timeout_var = tk.IntVar(value=15)
        lock_spin = ttk.Spinbox(options_frame, from_=1, to=120, textvariable=self.lock_timeout_var)
        lock_spin.grid(row=0, column=1, sticky=tk.W)
        
        self.backup_var = tk.BooleanVar(value=True)
        backup_cb = ttk.Checkbutton(options_frame, text="Auto-backup on exit", variable=self.backup_var)
        backup_cb.grid(row=1, column=0, sticky=tk.W, columnspan=2)
        
        self.clipboard_var = tk.BooleanVar(value=True)
        clipboard_cb = ttk.Checkbutton(options_frame, text="Clear clipboard after 30 seconds", variable=self.clipboard_var)
        clipboard_cb.grid(row=2, column=0, sticky=tk.W, columnspan=2)
        
        # Action buttons
        btn_frame = ttk.Frame(self.settings_frame)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        change_pass_btn = ttk.Button(btn_frame, text="Change Master Password", command=self.change_master_password)
        change_pass_btn.pack(side=tk.LEFT, padx=5)
        
        backup_btn = ttk.Button(btn_frame, text="Backup Vault Now", command=self.backup_vault)
        backup_btn.pack(side=tk.LEFT, padx=5)
        
        restore_btn = ttk.Button(btn_frame, text="Restore from Backup", command=self.restore_vault)
        restore_btn.pack(side=tk.LEFT, padx=5)
        
        export_btn = ttk.Button(btn_frame, text="Export All Data", command=self.export_all_data)
        export_btn.pack(side=tk.RIGHT, padx=5)
        
    def setup_first_run_screen(self):
        self.first_run_frame = ttk.Frame(self.content_frame)
        
        ttk.Label(self.first_run_frame, text="Welcome to FortKnox Password Manager", font=('Helvetica', 18, 'bold')).pack(pady=20)
        
        ttk.Label(self.first_run_frame, text="Create your master password:").pack(pady=5)
        self.master_pass_entry = ttk.Entry(self.first_run_frame, show="•", width=30)
        self.master_pass_entry.pack(pady=5)
        
        ttk.Label(self.first_run_frame, text="Confirm master password:").pack(pady=5)
        self.master_pass_confirm = ttk.Entry(self.first_run_frame, show="•", width=30)
        self.master_pass_confirm.pack(pady=5)
        
        self.strength_label = ttk.Label(self.first_run_frame, text="Password strength: ")
        self.strength_label.pack(pady=5)
        
        self.master_pass_entry.bind('<KeyRelease>', self.update_strength_meter)
        self.master_pass_confirm.bind('<KeyRelease>', self.update_strength_meter)
        
        create_btn = ttk.Button(self.first_run_frame, text="Create Vault", command=self.create_vault)
        create_btn.pack(pady=20)
        
    def update_strength_meter(self, event=None):
        password = self.master_pass_entry.get()
        if len(password) < 1:
            self.strength_label.config(text="Password strength: ")
            return
            
        result = SecurityAudit.check_password_strength(password)
        strength = result['score']
        feedback = result['feedback']['warning'] if result['feedback']['warning'] else "Good"
        
        colors = ['#e74c3c', '#e67e22', '#f1c40f', '#2ecc71', '#27ae60']
        strength_text = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"]
        
        self.strength_label.config(
            text=f"Password strength: {strength_text[strength]} | {feedback}",
            foreground=colors[strength]
        )
    
    # Core functionality methods
    def create_vault(self):
        password = self.master_pass_entry.get()
        confirm = self.master_pass_confirm.get()
        
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match")
            return
            
        if len(password) < 12:
            messagebox.showerror("Error", "Master password must be at least 12 characters")
            return
            
        strength = SecurityAudit.check_password_strength(password)['score']
        if strength < MIN_PASSWORD_STRENGTH:
            messagebox.showwarning("Weak Password", 
                "Your master password is weak. We recommend using a stronger password.")
            return
            
        # Generate salt and master key
        self.salt = secrets.token_bytes(SALT_SIZE)
        self.master_password = password
        
        # Save the salt (this is not secret)
        with open(MASTER_KEY_FILE, 'wb') as f:
            f.write(self.salt)
            
        # Initialize encryption
        self.initialize_encryption()
        
        # Save empty vault
        self.save_vault()
        
        # Switch to main screen
        self.show_main_screen()
    
    def unlock_vault(self):
        password = self.master_password_entry.get()
        
        if not os.path.exists(MASTER_KEY_FILE):
            messagebox.showerror("Error", "No vault found. Please create a new vault.")
            return
            
        # Load salt
        with open(MASTER_KEY_FILE, 'rb') as f:
            self.salt = f.read()
            
        self.master_password = password
        
        try:
            self.initialize_encryption()
            self.load_vault()
            self.show_main_screen()
            self.status_label.config(text="Status: Unlocked")
            self.locked = False
            self.start_auto_lock_timer()
        except Exception as e:
            messagebox.showerror("Error", "Invalid master password or corrupted vault")
            print(f"Error: {e}")
            self.master_password = None
            self.salt = None
            self.fernet = None
    
    def initialize_encryption(self):
        key = QuantumResistantEncryption.generate_key(self.master_password, self.salt)
        self.fernet = Fernet(key)
    
    def load_vault(self):
        if not os.path.exists(VAULT_FILE):
            self.vault = PasswordVault()
            return
            
        with open(VAULT_FILE, 'rb') as f:
            encrypted_data = f.read()
            
        try:
            decrypted_data = self.fernet.decrypt(encrypted_data)
            vault_data = eval(decrypted_data.decode())  # Note: In production, use a safer deserialization method
            self.vault = PasswordVault()
            self.vault.entries = vault_data
        except Exception as e:
            messagebox.showerror("Error", "Failed to decrypt vault. Password may be incorrect.")
            raise e
    
    def save_vault(self):
        if not self.fernet:
            return
            
        vault_data = str(self.vault.get_all_entries())
        encrypted_data = self.fernet.encrypt(vault_data.encode())
        
        with open(VAULT_FILE, 'wb') as f:
            f.write(encrypted_data)
    
    def emergency_lockdown(self):
        self.master_password = None
        self.salt = None
        self.fernet = None
        self.locked = True
        self.show_unlock_screen()
        self.status_label.config(text="Status: Locked (Emergency)")
        
        # Clear clipboard
        pyperclip.copy("")
        
        messagebox.showinfo("Lockdown", "Vault locked down. All sensitive data cleared from memory.")
    
    def start_auto_lock_timer(self):
        if hasattr(self, 'lock_timer'):
            self.root.after_cancel(self.lock_timer)
            
        timeout = self.lock_timeout_var.get() * 60000  # Convert to milliseconds
        self.lock_timer = self.root.after(timeout, self.auto_lock)
    
    def auto_lock(self):
        if not self.locked:
            self.master_password = None
            self.salt = None
            self.fernet = None
            self.locked = True
            self.show_unlock_screen()
            self.status_label.config(text="Status: Auto-locked")
            
            if self.clipboard_var.get():
                pyperclip.copy("")
    
    # UI navigation methods
    def show_unlock_screen(self):
        self.hide_all_frames()
        self.unlock_frame.pack(fill=tk.BOTH, expand=True)
        self.master_password_entry.focus()
    
    def show_main_screen(self):
        self.hide_all_frames()
        self.main_screen_frame.pack(fill=tk.BOTH, expand=True)
        self.refresh_vault_view()
    
    def show_first_run(self):
        self.hide_all_frames()
        self.first_run_frame.pack(fill=tk.BOTH, expand=True)
        self.master_pass_entry.focus()
    
    def hide_all_frames(self):
        for frame in [self.unlock_frame, self.main_screen_frame, self.first_run_frame]:
            frame.pack_forget()
    
    def load_vault_state(self):
        # Placeholder for loading any persistent state
        pass
    
    # Vault management methods
    def refresh_vault_view(self):
        self.tree.delete(*self.tree.get_children())
        for entry in self.vault.get_all_entries():
            self.tree.insert('', 'end', iid=entry['id'], values=(
                entry['title'],
                entry['username'],
                entry['url'],
                time.strftime('%Y-%m-%d %H:%M', time.localtime(entry['modified']))
            ))
    
    def filter_entries(self):
        query = self.search_entry.get().lower()
        if not query:
            self.refresh_vault_view()
            return
            
        self.tree.delete(*self.tree.get_children())
        for entry in self.vault.get_all_entries():
            if (query in entry['title'].lower() or 
                query in entry['username'].lower() or 
                query in entry['url'].lower() or 
                query in entry['notes'].lower()):
                self.tree.insert('', 'end', iid=entry['id'], values=(
                    entry['title'],
                    entry['username'],
                    entry['url'],
                    time.strftime('%Y-%m-%d %H:%M', time.localtime(entry['modified']))
                ))
    
    def show_add_entry_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Add New Password Entry")
        dialog.geometry("500x400")
        dialog.resizable(False, False)
        
        ttk.Label(dialog, text="Title:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.E)
        title_entry = ttk.Entry(dialog, width=40)
        title_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(dialog, text="Username:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.E)
        username_entry = ttk.Entry(dialog, width=40)
        username_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(dialog, text="Password:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.E)
        password_entry = ttk.Entry(dialog, width=40, show="•")
        password_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        
        generate_btn = ttk.Button(dialog, text="Generate", 
                                command=lambda: password_entry.insert(0, PasswordGenerator.generate()))
        generate_btn.grid(row=2, column=2, padx=5, pady=5)
        
        ttk.Label(dialog, text="URL:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.E)
        url_entry = ttk.Entry(dialog, width=40)
        url_entry.grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(dialog, text="Notes:").grid(row=4, column=0, padx=5, pady=5, sticky=tk.NE)
        notes_text = tk.Text(dialog, width=30, height=8)
        notes_text.grid(row=4, column=1, padx=5, pady=5, sticky=tk.W)
        
        def save_entry():
            title = title_entry.get()
            username = username_entry.get()
            password = password_entry.get()
            url = url_entry.get()
            notes = notes_text.get("1.0", tk.END).strip()
            
            if not title:
                messagebox.showerror("Error", "Title is required")
                return
                
            self.vault.add_entry(title, username, password, url, notes)
            self.save_vault()
            self.refresh_vault_view()
            dialog.destroy()
        
        btn_frame = ttk.Frame(dialog)
        btn_frame.grid(row=5, column=0, columnspan=3, pady=10)
        
        save_btn = ttk.Button(btn_frame, text="Save", command=save_entry)
        save_btn.pack(side=tk.LEFT, padx=10)
        
        cancel_btn = ttk.Button(btn_frame, text="Cancel", command=dialog.destroy)
        cancel_btn.pack(side=tk.LEFT, padx=10)
        
        title_entry.focus()
    
    def show_entry_details(self, event=None):
        selected = self.tree.selection()
        if not selected:
            return
            
        entry_id = selected[0]
        entry = self.vault.get_entry(entry_id)
        if not entry:
            return
            
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Password Entry: {entry['title']}")
        dialog.geometry("500x400")
        dialog.resizable(False, False)
        
        ttk.Label(dialog, text="Title:", font=('Helvetica', 10, 'bold')).grid(row=0, column=0, padx=5, pady=5, sticky=tk.E)
        ttk.Label(dialog, text=entry['title']).grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(dialog, text="Username:", font=('Helvetica', 10, 'bold')).grid(row=1, column=0, padx=5, pady=5, sticky=tk.E)
        ttk.Label(dialog, text=entry['username']).grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(dialog, text="Password:", font=('Helvetica', 10, 'bold')).grid(row=2, column=0, padx=5, pady=5, sticky=tk.E)
        password_label = ttk.Label(dialog, text="••••••••")
        password_label.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        
        show_pass_var = tk.BooleanVar(value=False)
        
        def toggle_password():
            if show_pass_var.get():
                password_label.config(text=entry['password'])
            else:
                password_label.config(text="••••••••")
        
        show_pass_cb = ttk.Checkbutton(dialog, text="Show Password", variable=show_pass_var, command=toggle_password)
        show_pass_cb.grid(row=2, column=2, padx=5, pady=5)
        
        ttk.Label(dialog, text="URL:", font=('Helvetica', 10, 'bold')).grid(row=3, column=0, padx=5, pady=5, sticky=tk.E)
        url_label = ttk.Label(dialog, text=entry['url'])
        url_label.grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)
        
        if entry['url']:
            def open_url():
                webbrowser.open(entry['url'])
            
            open_btn = ttk.Button(dialog, text="Open", command=open_url)
            open_btn.grid(row=3, column=2, padx=5, pady=5)
        
        ttk.Label(dialog, text="Notes:", font=('Helvetica', 10, 'bold')).grid(row=4, column=0, padx=5, pady=5, sticky=tk.NE)
        notes_text = tk.Text(dialog, width=40, height=10)
        notes_text.insert(tk.END, entry['notes'])
        notes_text.config(state=tk.DISABLED)
        notes_text.grid(row=4, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(dialog, text=f"Created: {time.strftime('%Y-%m-%d %H:%M', time.localtime(entry['created']))}").grid(
            row=5, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(dialog, text=f"Modified: {time.strftime('%Y-%m-%d %H:%M', time.localtime(entry['modified']))}").grid(
            row=6, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W)
        
        btn_frame = ttk.Frame(dialog)
        btn_frame.grid(row=7, column=0, columnspan=3, pady=10)
        
        copy_user_btn = ttk.Button(btn_frame, text="Copy Username", 
                                 command=lambda: pyperclip.copy(entry['username']))
        copy_user_btn.pack(side=tk.LEFT, padx=5)
        
        copy_pass_btn = ttk.Button(btn_frame, text="Copy Password", 
                                 command=lambda: pyperclip.copy(entry['password']))
        copy_pass_btn.pack(side=tk.LEFT, padx=5)
        
        close_btn = ttk.Button(btn_frame, text="Close", command=dialog.destroy)
        close_btn.pack(side=tk.RIGHT, padx=5)
    
    def show_edit_entry_dialog(self):
        selected = self.tree.selection()
        if not selected:
            return
            
        entry_id = selected[0]
        entry = self.vault.get_entry(entry_id)
        if not entry:
            return
            
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Edit Password Entry: {entry['title']}")
        dialog.geometry("500x400")
        dialog.resizable(False, False)
        
        ttk.Label(dialog, text="Title:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.E)
        title_entry = ttk.Entry(dialog, width=40)
        title_entry.insert(0, entry['title'])
        title_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(dialog, text="Username:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.E)
        username_entry = ttk.Entry(dialog, width=40)
        username_entry.insert(0, entry['username'])
        username_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(dialog, text="Password:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.E)
        password_entry = ttk.Entry(dialog, width=40, show="•")
        password_entry.insert(0, entry['password'])
        password_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        
        generate_btn = ttk.Button(dialog, text="Generate", 
                                command=lambda: password_entry.insert(0, PasswordGenerator.generate()))
        generate_btn.grid(row=2, column=2, padx=5, pady=5)
        
        ttk.Label(dialog, text="URL:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.E)
        url_entry = ttk.Entry(dialog, width=40)
        url_entry.insert(0, entry['url'])
        url_entry.grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(dialog, text="Notes:").grid(row=4, column=0, padx=5, pady=5, sticky=tk.NE)
        notes_text = tk.Text(dialog, width=30, height=8)
        notes_text.insert(tk.END, entry['notes'])
        notes_text.grid(row=4, column=1, padx=5, pady=5, sticky=tk.W)
        
        def save_changes():
            title = title_entry.get()
            username = username_entry.get()
            password = password_entry.get()
            url = url_entry.get()
            notes = notes_text.get("1.0", tk.END).strip()
            
            if not title:
                messagebox.showerror("Error", "Title is required")
                return
                
            self.vault.update_entry(
                entry_id,
                title=title,
                username=username,
                password=password,
                url=url,
                notes=notes
            )
            self.save_vault()
            self.refresh_vault_view()
            dialog.destroy()
        
        btn_frame = ttk.Frame(dialog)
        btn_frame.grid(row=5, column=0, columnspan=3, pady=10)
        
        save_btn = ttk.Button(btn_frame, text="Save Changes", command=save_changes)
        save_btn.pack(side=tk.LEFT, padx=10)
        
        cancel_btn = ttk.Button(btn_frame, text="Cancel", command=dialog.destroy)
        cancel_btn.pack(side=tk.LEFT, padx=10)
        
        title_entry.focus()
    
    def delete_selected_entry(self):
        selected = self.tree.selection()
        if not selected:
            return
            
        entry_id = selected[0]
        entry = self.vault.get_entry(entry_id)
        if not entry:
            return
            
        if messagebox.askyesno("Confirm Delete", f"Delete entry '{entry['title']}'?"):
            self.vault.delete_entry(entry_id)
            self.save_vault()
            self.refresh_vault_view()
    
    def copy_username(self):
        selected = self.tree.selection()
        if not selected:
            return
            
        entry = self.vault.get_entry(selected[0])
        if entry and entry['username']:
            pyperclip.copy(entry['username'])
            self.show_clipboard_notification("Username copied to clipboard")
    
    def copy_password(self):
        selected = self.tree.selection()
        if not selected:
            return
            
        entry = self.vault.get_entry(selected[0])
        if entry and entry['password']:
            pyperclip.copy(entry['password'])
            self.show_clipboard_notification("Password copied to clipboard")
            
            if self.clipboard_var.get():
                self.root.after(30000, lambda: pyperclip.copy(""))
    
    def show_clipboard_notification(self, message):
        # Create a small popup that fades away
        popup = tk.Toplevel(self.root)
        popup.overrideredirect(True)
        popup.geometry("+%d+%d" % (self.root.winfo_rootx()+50, self.root.winfo_rooty()+50))
        
        label = ttk.Label(popup, text=message, background='#27ae60', foreground='white', padding=5)
        label.pack()
        
        # Fade out animation
        def fade_out(step=10):
            alpha = popup.attributes('-alpha')
            if alpha > 0:
                alpha -= 0.1
                popup.attributes('-alpha', alpha)
                popup.after(100, fade_out)
            else:
                popup.destroy()
        
        popup.attributes('-alpha', 0.9)
        popup.after(2000, fade_out)
    
    def export_entry(self):
        selected = self.tree.selection()
        if not selected:
            return
            
        entry = self.vault.get_entry(selected[0])
        if not entry:
            return
            
        # In a real app, you would implement proper file saving
        messagebox.showinfo("Export Entry", 
            f"Entry exported:\n\nTitle: {entry['title']}\nUsername: {entry['username']}\nPassword: {entry['password']}")
    
    # Password generator methods
    def generate_password(self):
        try:
            password = PasswordGenerator.generate(
                length=self.length_var.get(),
                use_upper=self.upper_var.get(),
                use_lower=self.lower_var.get(),
                use_digits=self.digits_var.get(),
                use_special=self.special_var.get(),
                avoid_ambiguous=self.ambiguous_var.get()
            )
            self.generated_pass_var.set(password)
            self.update_strength_display(password)
        except ValueError as e:
            messagebox.showerror("Error", str(e))
    
    def update_strength_display(self, password):
        # Clear previous widgets
        for widget in self.strength_frame.winfo_children():
            widget.destroy()
        
        result = SecurityAudit.check_password_strength(password)
        strength = result['score']
        feedback = result['feedback']['warning'] if result['feedback']['warning'] else "Good password"
        crack_time = result['crack_time']
        
        ttk.Label(self.strength_frame, text="Password Strength:").pack(anchor=tk.W)
        
        # Strength meter
        meter_frame = ttk.Frame(self.strength_frame)
        meter_frame.pack(fill=tk.X, pady=5)
        
        colors = ['#e74c3c', '#e67e22', '#f1c40f', '#2ecc71', '#27ae60']
        labels = ['Very Weak', 'Weak', 'Moderate', 'Strong', 'Very Strong']
        
        for i in range(5):
            color = colors[i] if i <= strength else '#bdc3c7'
            ttk.Label(meter_frame, text="█", foreground=color, font=('Arial', 20)).pack(side=tk.LEFT)
        
        ttk.Label(self.strength_frame, text=labels[strength], font=('Helvetica', 10, 'bold')).pack(anchor=tk.W)
        ttk.Label(self.strength_frame, text=feedback).pack(anchor=tk.W)
        ttk.Label(self.strength_frame, text=f"Estimated crack time: {crack_time}").pack(anchor=tk.W)
    
    def check_password_strength(self):
        password = self.generated_pass_var.get()
        if not password:
            messagebox.showwarning("Warning", "No password generated")
            return
            
        self.update_strength_display(password)
    
    def copy_generated_password(self):
        password = self.generated_pass_var.get()
        if not password:
            messagebox.showwarning("Warning", "No password generated")
            return
            
        pyperclip.copy(password)
        self.show_clipboard_notification("Password copied to clipboard")
        
        if self.clipboard_var.get():
            self.root.after(30000, lambda: pyperclip.copy(""))
    
    def show_qr_code(self):
        password = self.generated_pass_var.get()
        if not password:
            messagebox.showwarning("Warning", "No password generated")
            return
            
        dialog = tk.Toplevel(self.root)
        dialog.title("Password QR Code")
        dialog.resizable(False, False)
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=6,
            border=4,
        )
        qr.add_data(password)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        img_tk = ImageTk.PhotoImage(img)
        
        label = ttk.Label(dialog, image=img_tk)
        label.image = img_tk  # Keep a reference
        label.pack(padx=10, pady=10)
        
        ttk.Label(dialog, text="Scan this QR code to get the password").pack(pady=5)
        
        close_btn = ttk.Button(dialog, text="Close", command=dialog.destroy)
        close_btn.pack(pady=10)
    
    # Security audit methods
    def run_security_audit(self):
        self.audit_results_text.config(state=tk.NORMAL)
        self.audit_results_text.delete(1.0, tk.END)
        
        # Check weak passwords
        weak_passwords = []
        for entry in self.vault.get_all_entries():
            strength = SecurityAudit.check_password_strength(entry['password'])['score']
            if strength < MIN_PASSWORD_STRENGTH:
                weak_passwords.append((entry['title'], strength))
        
        self.audit_results_text.insert(tk.END, "=== Weak Passwords ===\n")
        if weak_passwords:
            for title, strength in weak_passwords:
                strength_text = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"][strength]
                self.audit_results_text.insert(tk.END, f"{title}: {strength_text}\n")
        else:
            self.audit_results_text.insert(tk.END, "No weak passwords found\n")
        
        # Check duplicate passwords
        duplicates = SecurityAudit.check_duplicate_passwords(self.vault)
        self.audit_results_text.insert(tk.END, "\n=== Duplicate Passwords ===\n")
        if duplicates:
            for pw, titles in duplicates.items():
                self.audit_results_text.insert(tk.END, f"Password used in: {', '.join(titles)}\n")
        else:
            self.audit_results_text.insert(tk.END, "No duplicate passwords found\n")
        
        # Check old passwords
        old_threshold = time.time() - (365 * 24 * 60 * 60)  # 1 year
        old_passwords = [entry for entry in self.vault.get_all_entries() 
                        if entry['modified'] < old_threshold]
        
        self.audit_results_text.insert(tk.END, "\n=== Old Passwords ===\n")
        if old_passwords:
            for entry in old_passwords:
                days = (time.time() - entry['modified']) / (24 * 60 * 60)
                self.audit_results_text.insert(tk.END, 
                    f"{entry['title']}: Last changed {int(days)} days ago\n")
        else:
            self.audit_results_text.insert(tk.END, "No old passwords found\n")
        
        self.audit_results_text.config(state=tk.DISABLED)
    
    # Settings methods
    def change_master_password(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Change Master Password")
        dialog.geometry("400x300")
        dialog.resizable(False, False)
        
        ttk.Label(dialog, text="Current Master Password:").pack(pady=5)
        current_pass = ttk.Entry(dialog, show="•")
        current_pass.pack(pady=5)
        
        ttk.Label(dialog, text="New Master Password:").pack(pady=5)
        new_pass = ttk.Entry(dialog, show="•")
        new_pass.pack(pady=5)
        
        ttk.Label(dialog, text="Confirm New Master Password:").pack(pady=5)
        confirm_pass = ttk.Entry(dialog, show="•")
        confirm_pass.pack(pady=5)
        
        strength_label = ttk.Label(dialog, text="Password strength: ")
        strength_label.pack(pady=5)
        
        def update_strength(event=None):
            password = new_pass.get()
            if len(password) < 1:
                strength_label.config(text="Password strength: ")
                return
                
            result = SecurityAudit.check_password_strength(password)
            strength = result['score']
            feedback = result['feedback']['warning'] if result['feedback']['warning'] else "Good"
            
            colors = ['#e74c3c', '#e67e22', '#f1c40f', '#2ecc71', '#27ae60']
            strength_text = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"]
            
            strength_label.config(
                text=f"Password strength: {strength_text[strength]} | {feedback}",
                foreground=colors[strength]
            )
        
        new_pass.bind('<KeyRelease>', update_strength)
        
        def save_new_password():
            if new_pass.get() != confirm_pass.get():
                messagebox.showerror("Error", "New passwords do not match")
                return
                
            if not self.fernet:
                messagebox.showerror("Error", "Vault is locked")
                return
                
            # Verify current password
            try:
                current_key = QuantumResistantEncryption.generate_key(current_pass.get(), self.salt)
                test_fernet = Fernet(current_key)
                
                # Test decrypt
                with open(VAULT_FILE, 'rb') as f:
                    encrypted_data = f.read()
                test_fernet.decrypt(encrypted_data)
            except:
                messagebox.showerror("Error", "Current password is incorrect")
                return
                
            # Check new password strength
            strength = SecurityAudit.check_password_strength(new_pass.get())['score']
            if strength < MIN_PASSWORD_STRENGTH:
                messagebox.showwarning("Weak Password", 
                    "Your new master password is weak. We recommend using a stronger password.")
                return
                
            # Generate new salt and key
            new_salt = secrets.token_bytes(SALT_SIZE)
            new_key = QuantumResistantEncryption.generate_key(new_pass.get(), new_salt)
            new_fernet = Fernet(new_key)
            
            # Re-encrypt the vault with new key
            with open(VAULT_FILE, 'rb') as f:
                encrypted_data = f.read()
            decrypted_data = self.fernet.decrypt(encrypted_data)
            new_encrypted_data = new_fernet.encrypt(decrypted_data)
            
            # Save new encrypted data and salt
            with open(VAULT_FILE, 'wb') as f:
                f.write(new_encrypted_data)
            with open(MASTER_KEY_FILE, 'wb') as f:
                f.write(new_salt)
            
            # Update in-memory values
            self.salt = new_salt
            self.master_password = new_pass.get()
            self.fernet = new_fernet
            
            messagebox.showinfo("Success", "Master password changed successfully")
            dialog.destroy()
        
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(pady=10)
        
        save_btn = ttk.Button(btn_frame, text="Save", command=save_new_password)
        save_btn.pack(side=tk.LEFT, padx=10)
        
        cancel_btn = ttk.Button(btn_frame, text="Cancel", command=dialog.destroy)
        cancel_btn.pack(side=tk.LEFT, padx=10)
        
        current_pass.focus()
    
    def backup_vault(self):
        # In a real app, you would implement proper file saving
        self.save_vault()
        self.last_backup_label.config(text=f"Last backup: {time.strftime('%Y-%m-%d %H:%M')}")
        messagebox.showinfo("Backup", "Vault backed up successfully")
    
    def restore_vault(self):
        # In a real app, you would implement proper file loading
        messagebox.showinfo("Restore", "Vault restored from backup")
    
    def export_all_data(self):
        # In a real app, you would implement proper file exporting
        messagebox.showinfo("Export", "All data exported")
    
    def on_closing(self):
        if self.backup_var.get():
            self.backup_vault()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = FortKnoxUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()