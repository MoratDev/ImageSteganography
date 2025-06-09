import os
import sys
import numpy as np
from PIL import Image, ImageTk, ImageDraw, ImageFont
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import pickle
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import threading
import io
import random

COLORS = {
    "primary": "#2c3e50",
    "secondary": "#34495e",
    "accent": "#3498db",
    "accent_dark": "#2980b9",
    "success": "#2ecc71",
    "warning": "#f39c12",
    "danger": "#e74c3c",
    "background": "#ecf0f1",
    "text": "#2c3e50",
    "text_light": "#7f8c8d"
}

class SteganographyLogic:
    def __init__(self):
        self.header_size = 24
        
    def _generate_key(self):
        """Generate a random encryption key"""
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(os.urandom(32)))
        return key, salt
    
    def _encrypt_data(self, data, key):
        """Encrypt the data using the provided key"""
        f = Fernet(key)
        return f.encrypt(data)
    
    def _decrypt_data(self, encrypted_data, key):
        """Decrypt the data using the provided key"""
        f = Fernet(key)
        return f.decrypt(encrypted_data)
    
    def _prepare_image(self, image_path):
        """Open and convert image to RGB if needed"""
        img = Image.open(image_path)
        if img.mode != 'RGB':
            img = img.convert('RGB')
        return img
    
    def _calculate_capacity(self, img):
        """Calculate how many bytes can be stored in the image"""
        return (img.width * img.height * 3) // 8 - self.header_size
    
    def hide_file(self, input_image_path, file_to_hide_path, output_image_path=None, progress_callback=None):
        """Embed a file into an image"""
        img = self._prepare_image(input_image_path)
        width, height = img.size
        
        capacity = self._calculate_capacity(img)
        
        with open(file_to_hide_path, 'rb') as f:
            file_data = f.read()
            
        file_name = os.path.basename(file_to_hide_path)
        file_size = len(file_data)
        
        if file_size > capacity:
            return {"success": False, "message": f"Error: File is too large ({file_size} bytes) for this image (capacity: {capacity} bytes)"}
            
        key, salt = self._generate_key()
        
        encrypted_data = self._encrypt_data(file_data, key)
        
        metadata = {
            'filename': file_name,
            'filesize': file_size,
            'salt': salt
        }
        metadata_bytes = pickle.dumps(metadata)
        
        header_length = len(metadata_bytes).to_bytes(2, byteorder='big')
        data_to_hide = header_length + metadata_bytes + encrypted_data
        total_size = len(data_to_hide)
        
        img_array = np.array(img)
        
        flat_array = img_array.reshape(-1)
        
        modified_flat_array = flat_array.copy()
        
        bit_index = 0
        for byte_index, data_byte in enumerate(data_to_hide):
            if progress_callback and byte_index % 100 == 0:
                progress = byte_index / len(data_to_hide) * 100
                progress_callback(progress)
                
            for bit in range(8):
                bit_value = (data_byte >> bit) & 1
                
                if bit_value == 1:
                    modified_flat_array[bit_index] = np.uint8((modified_flat_array[bit_index] & 0xFE) | 1)
                else:
                    modified_flat_array[bit_index] = np.uint8((modified_flat_array[bit_index] & 0xFE))
                    
                bit_index += 1
                
                if bit_index >= len(modified_flat_array):
                    return {"success": False, "message": "Error: Not enough space in the image"}
        
        if progress_callback:
            progress_callback(100)
            
        modified_img_array = modified_flat_array.reshape(img_array.shape)
        
        modified_img = Image.fromarray(modified_img_array)
        
        if output_image_path is None:
            output_image_path = f"stego_{os.path.basename(input_image_path)}"
        modified_img.save(output_image_path)
        
        return {
            "success": True, 
            "message": f"File successfully hidden in {output_image_path}",
            "key": key.decode(),
            "output_path": output_image_path
        }
    
    def extract_file(self, stego_image_path, key, output_folder=".", progress_callback=None):
        """Extract a hidden file from an image using the provided key"""
        try:
            key = key.encode()
            
            img = self._prepare_image(stego_image_path)
            
            img_array = np.array(img)
            flat_array = img_array.reshape(-1)
            
            metadata_length_bits = []
            for i in range(16):
                metadata_length_bits.append(flat_array[i] & 1)
                
            metadata_length_bytes = bytearray()
            for i in range(0, 16, 8):
                byte_value = 0
                for bit in range(8):
                    byte_value |= (metadata_length_bits[i + bit] << bit)
                metadata_length_bytes.append(byte_value)
                
            metadata_length = int.from_bytes(metadata_length_bytes, byteorder='big')
            
            metadata_bits = []
            for i in range(16, 16 + metadata_length * 8):
                if i < len(flat_array):
                    metadata_bits.append(flat_array[i] & 1)
                else:
                    return {"success": False, "message": "Error: Image data is corrupted or incomplete"}
                
            metadata_bytes = bytearray()
            for i in range(0, len(metadata_bits), 8):
                if i + 8 <= len(metadata_bits):
                    byte_value = 0
                    for bit in range(8):
                        byte_value |= (metadata_bits[i + bit] << bit)
                    metadata_bytes.append(byte_value)
                    
            try:
                metadata = pickle.loads(metadata_bytes)
                file_name = metadata['filename']
                file_size = metadata['filesize']
                salt = metadata['salt']
            except Exception:
                return {"success": False, "message": "Error: Could not parse metadata. This may not be a valid stego image."}
            
            try:
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                Fernet(key)
            except Exception as e:
                return {"success": False, "message": "Error: Invalid key format or corrupted data"}
            
            data_start_bit = 16 + metadata_length * 8
            data_bits = []
            
            total_bits_to_extract = file_size * 8 * 2
            
            for i in range(data_start_bit, min(data_start_bit + total_bits_to_extract, len(flat_array))):
                data_bits.append(flat_array[i] & 1)
                    
                if progress_callback and i % 1000 == 0:
                    progress = (i - data_start_bit) / total_bits_to_extract * 100
                    progress_callback(min(progress, 90))
                    
            encrypted_data = bytearray()
            for i in range(0, len(data_bits), 8):
                if i + 8 <= len(data_bits):
                    byte_value = 0
                    for bit in range(8):
                        byte_value |= (data_bits[i + bit] << bit)
                    encrypted_data.append(byte_value)
                    
            if progress_callback:
                progress_callback(90)
            
            decrypted = False
            for length in range(file_size, len(encrypted_data)):
                try:
                    decrypted_data = self._decrypt_data(bytes(encrypted_data[:length]), key)
                    if len(decrypted_data) == file_size:
                        decrypted = True
                        break
                except Exception:
                    continue
                    
            if not decrypted:
                return {"success": False, "message": "Error: Could not decrypt the data. Invalid key or corrupted image."}
                
            output_path = os.path.join(output_folder, file_name)
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
                
            if progress_callback:
                progress_callback(100)
                
            return {
                "success": True, 
                "message": f"File successfully extracted to {output_path}",
                "output_path": output_path,
                "filename": file_name
            }
        except Exception as e:
            return {"success": False, "message": f"Error: {str(e)}"}

class HoverButton(ttk.Button):
    """Custom button with hover effect"""
    def __init__(self, master=None, **kwargs):
        self.defaultBackground = kwargs.get("background", "SystemButtonFace")
        self.hoverBackground = kwargs.pop("hover_background", COLORS["accent_dark"])
        self.activeBackground = kwargs.pop("active_background", COLORS["accent_dark"])
        
        ttk.Button.__init__(self, master, **kwargs)
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
        
    def on_enter(self, event):
        self.config(style="Hover.TButton")
        
    def on_leave(self, event):
        self.config(style="TButton")

class SteganoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        
        self.title("Image Steganography")
        self.geometry("950x680")
        self.configure(bg=COLORS["background"])
        self.resizable(True, True)
        
        try:
            icon = self.create_icon()
            icon_path = os.path.join(os.path.expanduser("~"), ".temp_stego_icon.ico")
            icon.save(icon_path)
            self.iconbitmap(icon_path)
        except Exception:
            pass
        
        self.steg = SteganographyLogic()
        
        self.setup_styles()
        
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        self.hide_tab = ttk.Frame(self.notebook, style="Card.TFrame")
        self.extract_tab = ttk.Frame(self.notebook, style="Card.TFrame")
        self.info_tab = ttk.Frame(self.notebook, style="Card.TFrame")
        
        self.notebook.add(self.hide_tab, text="Hide File")
        self.notebook.add(self.extract_tab, text="Extract File")
        self.notebook.add(self.info_tab, text="Image Info")
        
        self.setup_hide_tab()
        self.setup_extract_tab()
        self.setup_info_tab()
        
        footer_frame = ttk.Frame(self, style="Footer.TFrame")
        footer_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        footer = ttk.Label(
            footer_frame, 
            text="Secret Keeper © 2025 - Keep your data hidden in plain sight", 
            foreground=COLORS["text_light"],
            background=COLORS["secondary"],
            font=("Helvetica", 9)
        )
        footer.pack(side=tk.BOTTOM, pady=8)
    
    def create_icon(self):
        """Create a simple icon for the application"""
        size = 64
        icon = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(icon)
        
        lock_color = tuple(int(COLORS["accent"][1:][i:i+2], 16) for i in (0, 2, 4))
        
        draw.rectangle((16, 26, 48, 54), fill=lock_color)
        
        draw.arc((18, 10, 46, 38), 0, 180, fill=lock_color, width=5)
        
        draw.ellipse((28, 34, 36, 42), fill="white")
        draw.rectangle((30, 38, 34, 46), fill="white")
        
        draw.rectangle((10, 16, 22, 24), fill=(255, 255, 255, 180))
        draw.rectangle((12, 18, 20, 22), fill=(0, 200, 0, 180))
        
        return icon
        
    def setup_styles(self):
        """Setup custom styles for the application"""
        self.style = ttk.Style()
        
        try:
            self.style.theme_use('clam')
        except tk.TclError:
            pass
        
        self.style.configure('TFrame', background=COLORS["background"])
        self.style.configure('Card.TFrame', background=COLORS["background"], relief="solid", borderwidth=0)
        self.style.configure('Footer.TFrame', background=COLORS["secondary"])
        
        self.style.configure('TLabel', 
                             background=COLORS["background"], 
                             foreground=COLORS["text"], 
                             font=('Helvetica', 10))
        self.style.configure('Header.TLabel', 
                             background=COLORS["background"], 
                             foreground=COLORS["primary"], 
                             font=('Helvetica', 18, 'bold'))
        self.style.configure('Subheader.TLabel', 
                             background=COLORS["background"], 
                             foreground=COLORS["primary"], 
                             font=('Helvetica', 14, 'bold'))
        
        self.style.configure('TButton', 
                             font=('Helvetica', 10), 
                             background=COLORS["accent"],
                             foreground="white")
        self.style.configure('Accent.TButton', 
                             font=('Helvetica', 11, 'bold'),
                             background=COLORS["accent"],
                             foreground="white")
        self.style.configure('Hover.TButton', 
                             background=COLORS["accent_dark"],
                             foreground="white")
        
        self.style.configure('TEntry', foreground=COLORS["text"])
        
        self.style.configure('TScrollbar', background=COLORS["background"], troughcolor=COLORS["background"])
        
        self.style.configure('TNotebook', background=COLORS["background"], borderwidth=0)
        self.style.configure('TNotebook.Tab', 
                           background=COLORS["secondary"], 
                           foreground="white",
                           padding=(10, 5),
                           font=('Helvetica', 10, 'bold'))
        self.style.map('TNotebook.Tab', 
                     background=[('selected', COLORS["accent"])],
                     foreground=[('selected', "white")])
        
        self.style.configure("TProgressbar", 
                           thickness=20,
                           troughcolor=COLORS["background"],
                           background=COLORS["accent"])

    def setup_hide_tab(self):
        main_frame = ttk.Frame(self.hide_tab)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        header = ttk.Label(main_frame, text="Hide a File in an Image", style='Header.TLabel')
        header.pack(pady=(0, 20))
        
        img_frame = ttk.Frame(main_frame)
        img_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(img_frame, text="Select Carrier Image:").pack(side=tk.LEFT)
        self.hide_image_path = tk.StringVar()
        ttk.Entry(img_frame, textvariable=self.hide_image_path, width=50).pack(side=tk.LEFT, padx=5)
        ttk.Button(img_frame, text="Browse...", command=self.browse_hide_image).pack(side=tk.LEFT)
        
        file_frame = ttk.Frame(main_frame)
        file_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(file_frame, text="Select File to Hide:").pack(side=tk.LEFT)
        self.hide_file_path = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.hide_file_path, width=50).pack(side=tk.LEFT, padx=5)
        ttk.Button(file_frame, text="Browse...", command=self.browse_hide_file).pack(side=tk.LEFT)
        
        output_frame = ttk.Frame(main_frame)
        output_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(output_frame, text="Output Image:").pack(side=tk.LEFT)
        self.output_image_path = tk.StringVar()
        ttk.Entry(output_frame, textvariable=self.output_image_path, width=50).pack(side=tk.LEFT, padx=5)
        ttk.Button(output_frame, text="Browse...", command=self.browse_output_image).pack(side=tk.LEFT)
        
        preview_frame = ttk.Frame(main_frame)
        preview_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        left_frame = ttk.Frame(preview_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        ttk.Label(left_frame, text="Image Preview:", style='Subheader.TLabel').pack(pady=5)
        
        preview_container = ttk.Frame(left_frame, style="Card.TFrame")
        preview_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.hide_image_preview = ttk.Label(preview_container, background="#ddd")
        self.hide_image_preview.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        right_frame = ttk.Frame(preview_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        ttk.Label(right_frame, text="File Information:", style='Subheader.TLabel').pack(pady=5)
        
        info_container = ttk.Frame(right_frame, style="Card.TFrame")
        info_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.hide_file_info = ScrolledText(
            info_container, 
            height=10, 
            width=40, 
            wrap=tk.WORD,
            font=("Helvetica", 10),
            bg="white",
            bd=0,
            relief="flat"
        )
        self.hide_file_info.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        progress_frame = ttk.Frame(main_frame)
        progress_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(progress_frame, text="Progress:").pack(side=tk.LEFT)
        self.hide_progress = ttk.Progressbar(
            progress_frame, 
            length=650, 
            mode='determinate',
            style="TProgressbar"
        )
        self.hide_progress.pack(side=tk.RIGHT, padx=5)
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        self.hide_button = ttk.Button(
            button_frame, 
            text="Hide File", 
            command=self.hide_file_button_click,
            style="Accent.TButton"
        )
        self.hide_button.pack(side=tk.RIGHT)
        
        results_frame = ttk.Frame(main_frame)
        results_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(results_frame, text="Encryption Key:").pack(side=tk.LEFT)
        self.encryption_key = tk.StringVar()
        self.key_entry = ttk.Entry(results_frame, textvariable=self.encryption_key, width=50)
        self.key_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(results_frame, text="Copy", command=self.copy_key).pack(side=tk.LEFT)
        ttk.Button(results_frame, text="Save Key", command=self.save_key).pack(side=tk.LEFT, padx=5)
        
    def setup_extract_tab(self):
        main_frame = ttk.Frame(self.extract_tab)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        header = ttk.Label(main_frame, text="Extract a Hidden File", style='Header.TLabel')
        header.pack(pady=(0, 20))
        
        img_frame = ttk.Frame(main_frame)
        img_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(img_frame, text="Select Stego Image:").pack(side=tk.LEFT)
        self.extract_image_path = tk.StringVar()
        ttk.Entry(img_frame, textvariable=self.extract_image_path, width=50).pack(side=tk.LEFT, padx=5)
        ttk.Button(img_frame, text="Browse...", command=self.browse_extract_image).pack(side=tk.LEFT)
        
        key_frame = ttk.Frame(main_frame)
        key_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(key_frame, text="Encryption Key:").pack(side=tk.LEFT)
        self.extract_key = tk.StringVar()
        ttk.Entry(key_frame, textvariable=self.extract_key, width=50).pack(side=tk.LEFT, padx=5)
        ttk.Button(key_frame, text="Load Key", command=self.load_key).pack(side=tk.LEFT)
        
        output_frame = ttk.Frame(main_frame)
        output_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(output_frame, text="Output Folder:").pack(side=tk.LEFT)
        self.output_folder = tk.StringVar()
        self.output_folder.set(os.getcwd())
        ttk.Entry(output_frame, textvariable=self.output_folder, width=50).pack(side=tk.LEFT, padx=5)
        ttk.Button(output_frame, text="Browse...", command=self.browse_output_folder).pack(side=tk.LEFT)
        
        preview_frame = ttk.Frame(main_frame)
        preview_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        preview_container = ttk.Frame(preview_frame, style="Card.TFrame")
        preview_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        ttk.Label(preview_container, text="Image Preview:", style='Subheader.TLabel').pack(pady=5)
        
        self.extract_image_preview = ttk.Label(preview_container, background="#ddd")
        self.extract_image_preview.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        progress_frame = ttk.Frame(main_frame)
        progress_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(progress_frame, text="Progress:").pack(side=tk.LEFT)
        self.extract_progress = ttk.Progressbar(
            progress_frame, 
            length=650, 
            mode='determinate',
            style="TProgressbar"
        )
        self.extract_progress.pack(side=tk.RIGHT, padx=5)
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        self.extract_button = ttk.Button(
            button_frame, 
            text="Extract File", 
            command=self.extract_file_button_click,
            style="Accent.TButton"
        )
        self.extract_button.pack(side=tk.RIGHT)
        
        result_container = ttk.Frame(main_frame, style="Card.TFrame")
        result_container.pack(fill=tk.X, pady=5)
        
        self.extract_result = ttk.Label(
            result_container, 
            text="Extraction results will appear here...",
            foreground=COLORS["text_light"]
        )
        self.extract_result.pack(fill=tk.X, pady=10, padx=10)
        
    def setup_info_tab(self):
        main_frame = ttk.Frame(self.info_tab)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        header = ttk.Label(main_frame, text="Image Information", style='Header.TLabel')
        header.pack(pady=(0, 20))
        
        img_frame = ttk.Frame(main_frame)
        img_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(img_frame, text="Select Image:").pack(side=tk.LEFT)
        self.info_image_path = tk.StringVar()
        ttk.Entry(img_frame, textvariable=self.info_image_path, width=50).pack(side=tk.LEFT, padx=5)
        ttk.Button(img_frame, text="Browse...", command=self.browse_info_image).pack(side=tk.LEFT)
        
        content_frame = ttk.Frame(main_frame)
        content_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        left_frame = ttk.Frame(content_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        ttk.Label(left_frame, text="Image Preview:", style='Subheader.TLabel').pack(pady=5)
        
        preview_container = ttk.Frame(left_frame, style="Card.TFrame")
        preview_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.info_image_preview = ttk.Label(preview_container, background="#ddd")
        self.info_image_preview.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        right_frame = ttk.Frame(content_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        ttk.Label(right_frame, text="Image Details:", style='Subheader.TLabel').pack(pady=5)
        
        info_container = ttk.Frame(right_frame, style="Card.TFrame")
        info_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.image_info = ScrolledText(
            info_container, 
            height=15, 
            width=40, 
            wrap=tk.WORD,
            font=("Helvetica", 10),
            bg="white",
            bd=0,
            relief="flat"
        )
        self.image_info.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(
            button_frame, 
            text="Analyze Image", 
            command=self.analyze_image,
            style="Accent.TButton"
        ).pack(side=tk.RIGHT)
        
    def browse_hide_image(self):
        path = filedialog.askopenfilename(
            title="Select Image",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp *.gif"), ("All files", "*.*")]
        )
        if path:
            self.hide_image_path.set(path)
            self.load_hide_image_preview()
            self.check_capacity()
            
    def browse_hide_file(self):
        path = filedialog.askopenfilename(
            title="Select File to Hide",
            filetypes=[("All files", "*.*")]
        )
        if path:
            self.hide_file_path.set(path)
            self.update_file_info()
            self.update_output_path()
            self.check_capacity()
            
    def browse_output_image(self):
        path = filedialog.asksaveasfilename(
            title="Save Output Image",
            filetypes=[("PNG files", "*.png"), ("All files", "*.*")],
            defaultextension=".png"
        )
        if path:
            self.output_image_path.set(path)
            
    def browse_extract_image(self):
        path = filedialog.askopenfilename(
            title="Select Stego Image",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp *.gif"), ("All files", "*.*")]
        )
        if path:
            self.extract_image_path.set(path)
            self.load_extract_image_preview()
            
    def browse_output_folder(self):
        path = filedialog.askdirectory(title="Select Output Folder")
        if path:
            self.output_folder.set(path)
            
    def browse_info_image(self):
        path = filedialog.askopenfilename(
            title="Select Image",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp *.gif"), ("All files", "*.*")]
        )
        if path:
            self.info_image_path.set(path)
            self.load_info_image_preview()
            self.analyze_image()
            
    def load_hide_image_preview(self):
        try:
            path = self.hide_image_path.get()
            if path:
                img = Image.open(path)
                img.thumbnail((300, 300))
                photo = ImageTk.PhotoImage(img)
                self.hide_image_preview.configure(image=photo)
                self.hide_image_preview.image = photo
        except Exception as e:
            messagebox.showerror("Error", f"Could not load image: {str(e)}")
            
    def load_extract_image_preview(self):
        try:
            path = self.extract_image_path.get()
            if path:
                img = Image.open(path)
                img.thumbnail((300, 300))
                photo = ImageTk.PhotoImage(img)
                self.extract_image_preview.configure(image=photo)
                self.extract_image_preview.image = photo
        except Exception as e:
            messagebox.showerror("Error", f"Could not load image: {str(e)}")
            
    def load_info_image_preview(self):
        try:
            path = self.info_image_path.get()
            if path:
                img = Image.open(path)
                img.thumbnail((300, 300))
                photo = ImageTk.PhotoImage(img)
                self.info_image_preview.configure(image=photo)
                self.info_image_preview.image = photo
        except Exception as e:
            messagebox.showerror("Error", f"Could not load image: {str(e)}")
            
    def update_file_info(self):
        try:
            path = self.hide_file_path.get()
            if path:
                file_size = os.path.getsize(path)
                file_name = os.path.basename(path)
                file_ext = os.path.splitext(file_name)[1]
                
                info_text = f"File Name: {file_name}\n"
                info_text += f"File Size: {self.format_size(file_size)}\n"
                info_text += f"File Type: {file_ext}\n"
                info_text += f"Last Modified: {self.format_date(os.path.getmtime(path))}\n"
                
                self.hide_file_info.config(state=tk.NORMAL)
                self.hide_file_info.delete(1.0, tk.END)
                self.hide_file_info.insert(tk.END, info_text)
                self.hide_file_info.config(state=tk.NORMAL)
        except Exception as e:
            self.hide_file_info.config(state=tk.NORMAL)
            self.hide_file_info.delete(1.0, tk.END)
            self.hide_file_info.insert(tk.END, f"Error loading file info: {str(e)}")
            self.hide_file_info.config(state=tk.NORMAL)
            
    def update_output_path(self):
        input_path = self.hide_image_path.get()
        if input_path and not self.output_image_path.get():
            dir_name = os.path.dirname(input_path)
            base_name = os.path.basename(input_path)
            name, ext = os.path.splitext(base_name)
            output_path = os.path.join(dir_name, f"stego_{name}.png")
            self.output_image_path.set(output_path)
            
    def check_capacity(self):
        try:
            image_path = self.hide_image_path.get()
            file_path = self.hide_file_path.get()
            
            if not image_path or not file_path:
                return
                
            img = self.steg._prepare_image(image_path)
            capacity = self.steg._calculate_capacity(img)
            file_size = os.path.getsize(file_path)
            
            self.hide_file_info.config(state=tk.NORMAL)
            info = self.hide_file_info.get(1.0, tk.END)
            if "Capacity Check" in info:
                self.hide_file_info.delete(1.0, tk.END)
                self.hide_file_info.insert(tk.END, info.split("Capacity Check:")[0])
                
            self.hide_file_info.insert(tk.END, "\n\nCapacity Check:\n")
            
            if file_size > capacity:
                self.hide_file_info.insert(tk.END, f"⚠️ File too large for this image!\n", "warning")
                self.hide_file_info.insert(tk.END, f"- File size: {self.format_size(file_size)}\n")
                self.hide_file_info.insert(tk.END, f"- Image capacity: {self.format_size(capacity)}\n")
                self.hide_file_info.insert(tk.END, f"- Need {self.format_size(file_size - capacity)} more space", "warning")
            else:
                self.hide_file_info.insert(tk.END, f"✓ File will fit in this image\n", "success")
                self.hide_file_info.insert(tk.END, f"- File size: {self.format_size(file_size)}\n")
                self.hide_file_info.insert(tk.END, f"- Image capacity: {self.format_size(capacity)}\n")
                self.hide_file_info.insert(tk.END, f"- Space remaining: {self.format_size(capacity - file_size)}")
            
            self.hide_file_info.tag_configure("success", foreground=COLORS["success"])
            self.hide_file_info.tag_configure("warning", foreground=COLORS["warning"])
            self.hide_file_info.config(state=tk.NORMAL)
        except FileNotFoundError:
            self.hide_file_info.config(state=tk.NORMAL)
            self.hide_file_info.insert(tk.END, "\n\nCapacity Check:\n")
            self.hide_file_info.insert(tk.END, f"⚠️ Error: File not found\n", "warning")
            self.hide_file_info.tag_configure("warning", foreground=COLORS["warning"])
            self.hide_file_info.config(state=tk.NORMAL)
        except PermissionError:
            self.hide_file_info.config(state=tk.NORMAL)
            self.hide_file_info.insert(tk.END, "\n\nCapacity Check:\n")
            self.hide_file_info.insert(tk.END, f"⚠️ Error: Permission denied when accessing file\n", "warning")
            self.hide_file_info.tag_configure("warning", foreground=COLORS["warning"])
            self.hide_file_info.config(state=tk.NORMAL)
        except Exception as e:
            self.hide_file_info.config(state=tk.NORMAL)
            self.hide_file_info.insert(tk.END, "\n\nCapacity Check:\n")
            self.hide_file_info.insert(tk.END, f"⚠️ Error: {str(e)}\n", "warning")
            self.hide_file_info.tag_configure("warning", foreground=COLORS["warning"])
            self.hide_file_info.config(state=tk.NORMAL)
    
    def hide_file_button_click(self):
        """Process to hide a file in an image when button is clicked"""
        if not self.hide_image_path.get():
            messagebox.showerror("Error", "Please select a carrier image")
            return
            
        if not self.hide_file_path.get():
            messagebox.showerror("Error", "Please select a file to hide")
            return
            
        if not self.output_image_path.get():
            messagebox.showerror("Error", "Please specify an output image path")
            return
            
        self.hide_button.configure(state="disabled")
        self.hide_progress['value'] = 0
        
        threading.Thread(target=self._run_hide_process).start()
    
    def _run_hide_process(self):
        """Execute the hide process in a background thread"""
        try:
            def progress_callback(value):
                self.hide_progress['value'] = value
                self.update_idletasks()
                
            result = self.steg.hide_file(
                self.hide_image_path.get(),
                self.hide_file_path.get(),
                self.output_image_path.get(),
                progress_callback
            )
            
            self.after(0, lambda: self._process_hide_result(result))
            
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Error", f"An error occurred: {str(e)}"))
            self.after(0, lambda: self.hide_button.configure(state="normal"))
    
    def _process_hide_result(self, result):
        """Process the result of the hide operation"""
        self.hide_button.configure(state="normal")
        
        if result["success"]:
            messagebox.showinfo("Success", result["message"])
            
            self.encryption_key.set(result["key"])
            
            self.key_entry.select_range(0, tk.END)
            self.key_entry.focus()
        else:
            messagebox.showerror("Error", result["message"])
    
    def extract_file_button_click(self):
        """Process to extract a file from a stego image"""
        if not self.extract_image_path.get():
            messagebox.showerror("Error", "Please select a stego image")
            return
            
        if not self.extract_key.get():
            messagebox.showerror("Error", "Please enter the encryption key")
            return
            
        self.extract_button.configure(state="disabled")
        self.extract_progress['value'] = 0
        self.extract_result.configure(text="Extracting file... Please wait.")
        
        threading.Thread(target=self._run_extract_process).start()
    
    def _run_extract_process(self):
        """Execute the extract process in a background thread"""
        try:
            def progress_callback(value):
                self.extract_progress['value'] = value
                self.update_idletasks()
                
            result = self.steg.extract_file(
                self.extract_image_path.get(),
                self.extract_key.get(),
                self.output_folder.get(),
                progress_callback
            )
            
            self.after(0, lambda: self._process_extract_result(result))
            
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Error", f"An error occurred: {str(e)}"))
            self.after(0, lambda: self.extract_button.configure(state="normal"))
            self.after(0, lambda: self.extract_result.configure(text="Extraction failed. See error message."))
    
    def _process_extract_result(self, result):
        """Process the result of the extract operation"""
        self.extract_button.configure(state="normal")
        
        if result["success"]:
            messagebox.showinfo("Success", result["message"])
            
            self.extract_result.configure(
                text=f"✓ File successfully extracted: {result['filename']}",
                foreground=COLORS["success"]
            )
            
            if messagebox.askyesno("Open File", "Do you want to open the extracted file?"):
                try:
                    if sys.platform == 'win32':
                        os.startfile(result["output_path"])
                    elif sys.platform == 'darwin':
                        import subprocess
                        subprocess.call(('open', result["output_path"]))
                    else:
                        import subprocess
                        subprocess.call(('xdg-open', result["output_path"]))
                except Exception as e:
                    messagebox.showerror("Error", f"Could not open file: {str(e)}")
        else:
            messagebox.showerror("Error", result["message"])
            self.extract_result.configure(
                text="⚠️ Extraction failed. See error message.",
                foreground=COLORS["danger"]
            )
    
    def analyze_image(self):
        """Analyze an image and display its information"""
        path = self.info_image_path.get()
        if not path:
            messagebox.showerror("Error", "Please select an image to analyze")
            return
            
        try:
            img = Image.open(path)
            
            stego_capacity = self.steg._calculate_capacity(img)
            
            file_size = os.path.getsize(path)
            file_name = os.path.basename(path)
            
            self.image_info.config(state=tk.NORMAL)
            self.image_info.delete(1.0, tk.END)
            
            self.image_info.insert(tk.END, "📄 Basic Information\n", "section")
            self.image_info.insert(tk.END, f"File Name: {file_name}\n")
            self.image_info.insert(tk.END, f"File Size: {self.format_size(file_size)}\n\n")
            
            self.image_info.insert(tk.END, "🖼️ Image Properties\n", "section")
            self.image_info.insert(tk.END, f"Format: {img.format}\n")
            self.image_info.insert(tk.END, f"Mode: {img.mode}\n")
            self.image_info.insert(tk.END, f"Dimensions: {img.width} × {img.height} pixels\n")
            self.image_info.insert(tk.END, f"Color Depth: {self.get_color_depth(img)} bits\n\n")
            
            self.image_info.insert(tk.END, "🔒 Steganography Capacity\n", "section")
            self.image_info.insert(tk.END, f"Maximum Data Size: {self.format_size(stego_capacity)}\n")
            self.image_info.insert(tk.END, f"Usable Pixels: {stego_capacity * 8 // 3:,} of {img.width * img.height:,}\n")
            
            percentage = (stego_capacity * 8 // 3) / (img.width * img.height) * 100
            self.image_info.insert(tk.END, f"Utilization: {percentage:.1f}% of pixels\n")
            
            if "stego" in path.lower() or path.startswith("stego_"):
                self.image_info.insert(tk.END, "\n⚠️ This file name suggests it might be a stego image.\n", "warning")
            
            self.image_info.insert(tk.END, "\n💡 Tip: ", "tip")
            self.image_info.insert(tk.END, "For best results, use PNG images with high resolution.")
                
            self.image_info.tag_configure("section", font=("Helvetica", 11, "bold"), foreground=COLORS["primary"])
            self.image_info.tag_configure("warning", foreground=COLORS["warning"])
            self.image_info.tag_configure("tip", foreground=COLORS["accent"], font=("Helvetica", 10, "bold"))
            
            self.image_info.config(state=tk.NORMAL)
            
        except Exception as e:
            messagebox.showerror("Error", f"Could not analyze image: {str(e)}")
    
    def get_color_depth(self, img):
        """Get the color depth of an image"""
        mode_depths = {
            '1': 1,
            'L': 8,
            'P': 8,
            'RGB': 24,
            'RGBA': 32,
            'CMYK': 32,
            'YCbCr': 24,
            'LAB': 24,
            'HSV': 24,
            'I': 32,
            'F': 32
        }
        return mode_depths.get(img.mode, 0)
    
    def format_size(self, size_bytes):
        """Format a file size in bytes to a human-readable string"""
        if size_bytes < 1024:
            return f"{size_bytes} bytes"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"
    
    def format_date(self, timestamp):
        """Format a timestamp to a human-readable date/time"""
        import datetime
        dt = datetime.datetime.fromtimestamp(timestamp)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    
    def copy_key(self):
        """Copy the encryption key to the clipboard"""
        key = self.encryption_key.get()
        if not key:
            messagebox.showerror("Error", "No key to copy")
            return
            
        self.clipboard_clear()
        self.clipboard_append(key)
        
        notification = tk.Toplevel(self)
        notification.overrideredirect(True)
        
        x = self.winfo_pointerx() + 10
        y = self.winfo_pointery() + 10
        notification.geometry(f"200x30+{x}+{y}")
        
        notification.configure(bg=COLORS["success"])
        tk.Label(
            notification, 
            text="Key copied to clipboard", 
            fg="white", 
            bg=COLORS["success"],
            font=("Helvetica", 10)
        ).pack(fill=tk.BOTH, expand=True)
        
        notification.after(1500, notification.destroy)
    
    def save_key(self):
        """Save the encryption key to a file"""
        if not self.encryption_key.get():
            messagebox.showerror("Error", "No key to save")
            return
            
        path = filedialog.asksaveasfilename(
            title="Save Encryption Key",
            filetypes=[("Text files", "*.txt"), ("Key files", "*.key"), ("All files", "*.*")],
            defaultextension=".key"
        )
        
        if path:
            try:
                with open(path, 'w') as f:
                    f.write(self.encryption_key.get())
                messagebox.showinfo("Success", f"Key saved to {path}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not save key: {str(e)}")
    
    def load_key(self):
        """Load an encryption key from a file"""
        path = filedialog.askopenfilename(
            title="Load Encryption Key",
            filetypes=[("Text files", "*.txt"), ("Key files", "*.key"), ("All files", "*.*")]
        )
        
        if path:
            try:
                with open(path, 'r') as f:
                    key = f.read().strip()
                self.extract_key.set(key)
                
                self.extract_result.configure(
                    text=f"Key loaded successfully",
                    foreground=COLORS["success"]
                )
            except Exception as e:
                messagebox.showerror("Error", f"Could not load key: {str(e)}")
    
def main():
    app = SteganoApp()
    app.mainloop()
    
if __name__ == "__main__":
    main()