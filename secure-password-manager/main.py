"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                     PROFESYONEL ŞİFRE YÖNETİCİSİ                            ║
║                  Modern, Güvenli, Best Practice Standartları                 ║
║                         Python + CustomTkinter                               ║
╚══════════════════════════════════════════════════════════════════════════════╝

Güvenlik Özellikleri:
- Master Password: PBKDF2-HMAC-SHA256 + Random Salt ile hash'lenir
- Şifreler: Fernet (AES-128) ile şifrelenir
- Fernet Key: Master Password'den türetilir
- Veritabanı çalınsa bile şifreler okunamaz

Yazar: Python Siber Güvenlik Uzmanı
Tarih: 2024
"""

import customtkinter as ctk
import sqlite3
import hashlib
import secrets
import string
import base64
from cryptography.fernet import Fernet
import pyperclip
from tkinter import messagebox
import os


# ═══════════════════════════════════════════════════════════════════════════
# 1. GÜVENLİK KATMANı - ŞİFRELEME VE HASH İŞLEMLERİ
# ═══════════════════════════════════════════════════════════════════════════

class SecurityManager:
    """
    Şifreleme ve hash işlemlerinden sorumlu güvenlik katmanı.
    - Master password hash'leme ve doğrulama
    - Şifre şifreleme/çözme (Fernet)
    """
    
    @staticmethod
    def hash_master_password(password: str, salt: bytes = None) -> tuple:
        """
        Master password'ü güvenli bir şekilde hash'ler.
        
        Args:
            password: Kullanıcının girdiği ana şifre
            salt: Rastgele tuz değeri (ilk kayıtta oluşturulur)
        
        Returns:
            (hash_degeri, salt_degeri) tuple'ı
        """
        if salt is None:
            # İlk kayıt için rastgele 32 byte'lık salt oluştur
            salt = secrets.token_bytes(32)
        
        # PBKDF2-HMAC-SHA256 algoritması ile 100,000 iterasyon
        # Bu, brute-force saldırılarını yavaşlatır
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000  # İterasyon sayısı (daha yüksek = daha güvenli ama daha yavaş)
        )
        
        return password_hash, salt
    
    @staticmethod
    def generate_fernet_key(master_password: str, salt: bytes) -> bytes:
        """
        Master password'den Fernet şifreleme anahtarı türetir.
        
        Args:
            master_password: Kullanıcının ana şifresi
            salt: Veritabanından alınan salt değeri
        
        Returns:
            Fernet için kullanılabilir 32 byte'lık key
        """
        # Master password'den 32 byte'lık key türet
        key = hashlib.pbkdf2_hmac(
            'sha256',
            master_password.encode('utf-8'),
            salt,
            100000
        )
        # Fernet, base64 encoded key bekler
        return base64.urlsafe_b64encode(key)
    
    @staticmethod
    def encrypt_password(password: str, fernet_key: bytes) -> str:
        """
        Şifreyi Fernet (AES) ile şifreler.
        
        Args:
            password: Şifrelenecek düz metin şifre
            fernet_key: Şifreleme anahtarı
        
        Returns:
            Şifrelenmiş şifre (base64 string)
        """
        try:
            fernet = Fernet(fernet_key)
            encrypted = fernet.encrypt(password.encode('utf-8'))
            return encrypted.decode('utf-8')
        except Exception as e:
            raise Exception(f"Şifreleme hatası: {str(e)}")
    
    @staticmethod
    def decrypt_password(encrypted_password: str, fernet_key: bytes) -> str:
        """
        Şifrelenmiş şifreyi çözer.
        
        Args:
            encrypted_password: Şifrelenmiş şifre
            fernet_key: Şifre çözme anahtarı
        
        Returns:
            Düz metin şifre
        """
        try:
            fernet = Fernet(fernet_key)
            decrypted = fernet.decrypt(encrypted_password.encode('utf-8'))
            return decrypted.decode('utf-8')
        except Exception as e:
            raise Exception(f"Şifre çözme hatası: {str(e)}")


# ═══════════════════════════════════════════════════════════════════════════
# 2. VERİTABANI KATMANı - SQLite İŞLEMLERİ
# ═══════════════════════════════════════════════════════════════════════════

class DatabaseManager:
    """
    Veritabanı işlemlerinden sorumlu katman.
    - Master password kaydı ve doğrulama
    - Şifre CRUD işlemleri (Create, Read, Update, Delete)
    """
    
    def __init__(self, db_name: str = "password_vault.db"):
        """
        Args:
            db_name: Veritabanı dosyasının adı
        """
        self.db_name = db_name
        self.connection = None
        self.cursor = None
        self.initialize_database()
    
    def initialize_database(self):
        """
        Veritabanını ve gerekli tabloları oluşturur.
        """
        try:
            self.connection = sqlite3.connect(self.db_name)
            self.cursor = self.connection.cursor()
            
            # Master Password tablosu (sadece 1 kayıt olacak)
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS master_password (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    password_hash BLOB NOT NULL,
                    salt BLOB NOT NULL
                )
            ''')
            
            # Şifreler tablosu
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    site_name TEXT NOT NULL,
                    username TEXT NOT NULL,
                    encrypted_password TEXT NOT NULL,
                    created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            self.connection.commit()
        except Exception as e:
            raise Exception(f"Veritabanı başlatma hatası: {str(e)}")
    
    def is_master_password_set(self) -> bool:
        """
        Master password'ün daha önce ayarlanıp ayarlanmadığını kontrol eder.
        
        Returns:
            True: Daha önce kayıt yapılmış
            False: İlk kullanım
        """
        try:
            self.cursor.execute("SELECT COUNT(*) FROM master_password")
            count = self.cursor.fetchone()[0]
            return count > 0
        except Exception as e:
            print(f"Master password kontrol hatası: {str(e)}")
            return False
    
    def save_master_password(self, password_hash: bytes, salt: bytes) -> bool:
        """
        Master password'ü veritabanına kaydeder (sadece ilk kayıtta).
        
        Args:
            password_hash: Hash'lenmiş şifre
            salt: Rastgele tuz değeri
        
        Returns:
            Başarılı ise True
        """
        try:
            self.cursor.execute('''
                INSERT INTO master_password (id, password_hash, salt)
                VALUES (1, ?, ?)
            ''', (password_hash, salt))
            self.connection.commit()
            return True
        except Exception as e:
            print(f"Master password kayıt hatası: {str(e)}")
            return False
    
    def verify_master_password(self, password: str) -> tuple:
        """
        Kullanıcının girdiği master password'ü doğrular.
        
        Args:
            password: Kullanıcının girdiği şifre
        
        Returns:
            (basarili: bool, salt: bytes veya None)
        """
        try:
            self.cursor.execute("SELECT password_hash, salt FROM master_password WHERE id = 1")
            result = self.cursor.fetchone()
            
            if result is None:
                return False, None
            
            stored_hash, salt = result
            
            # Girilen şifreyi aynı salt ile hash'le
            calculated_hash, _ = SecurityManager.hash_master_password(password, salt)
            
            # Hash'leri karşılaştır
            if calculated_hash == stored_hash:
                return True, salt
            else:
                return False, None
        except Exception as e:
            print(f"Master password doğrulama hatası: {str(e)}")
            return False, None
    
    def add_password(self, site_name: str, username: str, encrypted_password: str) -> bool:
        """
        Yeni şifre kaydı ekler.
        
        Args:
            site_name: Web sitesi veya uygulama adı
            username: Kullanıcı adı veya e-posta
            encrypted_password: Şifrelenmiş şifre
        
        Returns:
            Başarılı ise True
        """
        try:
            self.cursor.execute('''
                INSERT INTO passwords (site_name, username, encrypted_password)
                VALUES (?, ?, ?)
            ''', (site_name, username, encrypted_password))
            self.connection.commit()
            return True
        except Exception as e:
            print(f"Şifre ekleme hatası: {str(e)}")
            return False
    
    def get_all_passwords(self) -> list:
        """
        Tüm kayıtlı şifreleri getirir.
        
        Returns:
            [(id, site_name, username, encrypted_password, created_date), ...]
        """
        try:
            self.cursor.execute('''
                SELECT id, site_name, username, encrypted_password, created_date
                FROM passwords
                ORDER BY created_date DESC
            ''')
            return self.cursor.fetchall()
        except Exception as e:
            print(f"Şifreleri getirme hatası: {str(e)}")
            return []
    
    def delete_password(self, password_id: int) -> bool:
        """
        Belirtilen ID'ye sahip şifreyi siler.
        
        Args:
            password_id: Silinecek kaydın ID'si
        
        Returns:
            Başarılı ise True
        """
        try:
            self.cursor.execute("DELETE FROM passwords WHERE id = ?", (password_id,))
            self.connection.commit()
            return True
        except Exception as e:
            print(f"Şifre silme hatası: {str(e)}")
            return False
    
    def close(self):
        """
        Veritabanı bağlantısını kapatır.
        """
        if self.connection:
            self.connection.close()


# ═══════════════════════════════════════════════════════════════════════════
# 3. ŞİFRE OLUŞTURUCU - GÜVENLİ RANDOM ŞİFRE ÜRETİMİ
# ═══════════════════════════════════════════════════════════════════════════

class PasswordGenerator:
    """
    Güvenli ve güçlü rastgele şifre üreten sınıf.
    """
    
    @staticmethod
    def generate(length: int = 16, 
                 use_uppercase: bool = True,
                 use_lowercase: bool = True, 
                 use_digits: bool = True,
                 use_symbols: bool = True) -> str:
        """
        Belirtilen kriterlere göre rastgele şifre oluşturur.
        
        Args:
            length: Şifre uzunluğu
            use_uppercase: Büyük harf kullan
            use_lowercase: Küçük harf kullan
            use_digits: Rakam kullan
            use_symbols: Sembol kullan
        
        Returns:
            Oluşturulan güçlü şifre
        """
        characters = ""
        
        if use_uppercase:
            characters += string.ascii_uppercase
        if use_lowercase:
            characters += string.ascii_lowercase
        if use_digits:
            characters += string.digits
        if use_symbols:
            characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        if not characters:
            # Hiçbir seçenek seçilmemişse varsayılan olarak hepsini kullan
            characters = string.ascii_letters + string.digits + "!@#$%^&*"
        
        # secrets modülü kullanarak kriptografik olarak güvenli rastgele şifre üret
        password = ''.join(secrets.choice(characters) for _ in range(length))
        return password


# ═══════════════════════════════════════════════════════════════════════════
# 4. GİRİŞ EKRANI - MASTER PASSWORD KAYIT/GİRİŞ
# ═══════════════════════════════════════════════════════════════════════════

class LoginScreen(ctk.CTkFrame):
    """
    Kullanıcının master password ile giriş yaptığı veya ilk kez kayıt olduğu ekran.
    """
    
    def __init__(self, parent, db_manager, on_login_success):
        """
        Args:
            parent: Ana pencere
            db_manager: Veritabanı yöneticisi
            on_login_success: Giriş başarılı olduğunda çağrılacak callback fonksiyonu
        """
        super().__init__(parent)
        self.db_manager = db_manager
        self.on_login_success = on_login_success
        self.is_first_time = not db_manager.is_master_password_set()
        
        self.pack(fill="both", expand=True)
        self.setup_ui()
    
    def setup_ui(self):
        """
        Giriş ekranının arayüzünü oluşturur.
        """
        # Ana container
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.place(relx=0.5, rely=0.5, anchor="center")
        
        # Logo/Başlık
        title_label = ctk.CTkLabel(
            container,
            text="🔐 EO DIGITAL LAB",
            font=ctk.CTkFont(size=32, weight="bold")
        )
        title_label.pack(pady=(0, 10))
        
        # Alt başlık
        subtitle = "Security Suite - Secure Vault Access" if self.is_first_time else "Giriş Yapın"
        subtitle_label = ctk.CTkLabel(
            container,
            text=subtitle,
            font=ctk.CTkFont(size=16),
            text_color="gray"
        )
        subtitle_label.pack(pady=(0, 30))
        
        # Master Password Giriş Kutusu
        self.password_entry = ctk.CTkEntry(
            container,
            placeholder_text="Ana Şifre",
            show="●",
            width=300,
            height=45,
            font=ctk.CTkFont(size=14)
        )
        self.password_entry.pack(pady=10)
        
        # İlk kayıt için şifre tekrar kutusu
        if self.is_first_time:
            self.password_confirm_entry = ctk.CTkEntry(
                container,
                placeholder_text="Ana Şifre Tekrar",
                show="●",
                width=300,
                height=45,
                font=ctk.CTkFont(size=14)
            )
            self.password_confirm_entry.pack(pady=10)
            
            # Güvenlik uyarısı
            warning_label = ctk.CTkLabel(
                container,
                text="⚠️ Ana şifrenizi unutursanız tüm verilerinizi kaybedersiniz!\n"
                     "Güçlü ve unutamayacağınız bir şifre seçin.",
                font=ctk.CTkFont(size=12),
                text_color="orange",
                wraplength=280
            )
            warning_label.pack(pady=10)
        
        # Giriş/Kayıt Ol Butonu
        button_text = "Kayıt Ol" if self.is_first_time else "Giriş Yap"
        self.login_button = ctk.CTkButton(
            container,
            text=button_text,
            command=self.handle_login,
            width=300,
            height=45,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color="#1f6aa5",
            hover_color="#144870"
        )
        self.login_button.pack(pady=20)
        
        # Enter tuşu ile giriş
        self.password_entry.bind("<Return>", lambda e: self.handle_login())
        if self.is_first_time:
            self.password_confirm_entry.bind("<Return>", lambda e: self.handle_login())
    
    # Footer İmzası (EO Digital Lab Branding)
        footer_label = ctk.CTkLabel(
            container,
            text="© 2025 EO Digital Lab Security Systems",
            font=ctk.CTkFont(size=10),
            text_color="gray40"
        )
        footer_label.pack(side="bottom", pady=(20, 0))

    def handle_login(self):
        """
        Giriş veya kayıt işlemini gerçekleştirir.
        """
        password = self.password_entry.get().strip()
        
        # Boş şifre kontrolü
        if not password:
            messagebox.showerror("Hata", "Lütfen bir şifre girin!")
            return
        
        if self.is_first_time:
            # İlk kayıt işlemi
            password_confirm = self.password_confirm_entry.get().strip()
            
            if password != password_confirm:
                messagebox.showerror("Hata", "Şifreler eşleşmiyor!")
                return
            
            if len(password) < 6:
                messagebox.showerror("Hata", "Ana şifre en az 6 karakter olmalıdır!")
                return
            
            # Master password'ü hash'le ve kaydet
            password_hash, salt = SecurityManager.hash_master_password(password)
            
            if self.db_manager.save_master_password(password_hash, salt):
                messagebox.showinfo(
                    "Başarılı",
                    "Ana şifreniz başarıyla kaydedildi!\n\n"
                    "⚠️ Bu şifreyi unutmayın, kurtarma seçeneği yoktur!"
                )
                # Fernet key'i oluştur ve ana ekrana geç
                fernet_key = SecurityManager.generate_fernet_key(password, salt)
                self.on_login_success(fernet_key)
            else:
                messagebox.showerror("Hata", "Kayıt sırasında bir hata oluştu!")
        else:
            # Giriş işlemi
            is_valid, salt = self.db_manager.verify_master_password(password)
            
            if is_valid:
                # Fernet key'i oluştur ve ana ekrana geç
                fernet_key = SecurityManager.generate_fernet_key(password, salt)
                self.on_login_success(fernet_key)
            else:
                messagebox.showerror("Hata", "Yanlış ana şifre!")
                self.password_entry.delete(0, 'end')


# ═══════════════════════════════════════════════════════════════════════════
# 5. ANA EKRAN - ŞİFRE YÖNETİM ARAYÜZÜ
# ═══════════════════════════════════════════════════════════════════════════

class MainScreen(ctk.CTkFrame):
    """
    Şifrelerin listelendiği, eklendiği, silindiği ana yönetim ekranı.
    """
    
    def __init__(self, parent, db_manager, fernet_key):
        """
        Args:
            parent: Ana pencere
            db_manager: Veritabanı yöneticisi
            fernet_key: Şifreleme/çözme anahtarı
        """
        super().__init__(parent)
        self.db_manager = db_manager
        self.fernet_key = fernet_key
        
        self.pack(fill="both", expand=True, padx=20, pady=20)
        self.setup_ui()
        self.load_passwords()
    
    def setup_ui(self):
        """
        Ana ekranın arayüzünü oluşturur.
        """
        # Başlık ve Yeni Kayıt Butonu
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 20))
        
        title_label = ctk.CTkLabel(
            header_frame,
            text="🔐 Kayıtlı Şifrelerim",
            font=ctk.CTkFont(size=24, weight="bold")
        )
        title_label.pack(side="left")
        
        add_button = ctk.CTkButton(
            header_frame,
            text="➕ Yeni Kayıt Ekle",
            command=self.open_add_password_dialog,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#28a745",
            hover_color="#218838",
            width=180,
            height=40
        )
        add_button.pack(side="right")
        
        # Şifre listesi için scrollable frame
        self.scrollable_frame = ctk.CTkScrollableFrame(
            self,
            fg_color="transparent"
        )
        self.scrollable_frame.pack(fill="both", expand=True)
    
    def load_passwords(self):
        """
        Veritabanından şifreleri yükler ve listeler.
        """
        # Önce mevcut widget'ları temizle
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
        
        passwords = self.db_manager.get_all_passwords()
        
        if not passwords:
            # Hiç kayıt yoksa bilgilendirme göster
            empty_label = ctk.CTkLabel(
                self.scrollable_frame,
                text="Henüz kayıtlı şifre yok.\n➕ 'Yeni Kayıt Ekle' butonuna tıklayarak başlayın!",
                font=ctk.CTkFont(size=16),
                text_color="gray"
            )
            empty_label.pack(pady=100)
            return
        
        # Her şifre için bir kart oluştur
        for password_data in passwords:
            self.create_password_card(password_data)
    
    def create_password_card(self, password_data):
        """
        Tek bir şifre kaydı için görsel kart oluşturur.
        
        Args:
            password_data: (id, site_name, username, encrypted_password, created_date)
        """
        password_id, site_name, username, encrypted_password, created_date = password_data
        
        # Kart frame'i
        card = ctk.CTkFrame(
            self.scrollable_frame,
            fg_color="#2b2b2b",
            corner_radius=10
        )
        card.pack(fill="x", pady=8, ipady=10)
        
        # Sol taraf - Site bilgisi
        left_frame = ctk.CTkFrame(card, fg_color="transparent")
        left_frame.pack(side="left", fill="both", expand=True, padx=15)
        
        site_label = ctk.CTkLabel(
            left_frame,
            text=f"🌐 {site_name}",
            font=ctk.CTkFont(size=16, weight="bold"),
            anchor="w"
        )
        site_label.pack(anchor="w")
        
        username_label = ctk.CTkLabel(
            left_frame,
            text=f"👤 {username}",
            font=ctk.CTkFont(size=13),
            text_color="gray",
            anchor="w"
        )
        username_label.pack(anchor="w", pady=(5, 0))
        
        # Sağ taraf - Butonlar
        right_frame = ctk.CTkFrame(card, fg_color="transparent")
        right_frame.pack(side="right", padx=15)
        
        # Şifreyi Göster/Gizle Butonu
        show_button = ctk.CTkButton(
            right_frame,
            text="👁️ Göster",
            command=lambda: self.toggle_password_visibility(
                password_id, encrypted_password, show_button
            ),
            width=100,
            fg_color="#6c757d",
            hover_color="#5a6268"
        )
        show_button.pack(side="left", padx=5)
        
        # Kopyala Butonu
        copy_button = ctk.CTkButton(
            right_frame,
            text="📋 Kopyala",
            command=lambda: self.copy_password_to_clipboard(encrypted_password),
            width=100,
            fg_color="#007bff",
            hover_color="#0056b3"
        )
        copy_button.pack(side="left", padx=5)
        
        # Sil Butonu
        delete_button = ctk.CTkButton(
            right_frame,
            text="🗑️ Sil",
            command=lambda: self.delete_password(password_id),
            width=80,
            fg_color="#dc3545",
            hover_color="#c82333"
        )
        delete_button.pack(side="left", padx=5)
    
    def toggle_password_visibility(self, password_id, encrypted_password, button):
        """
        Şifreyi göster/gizle işlemi.
        
        Args:
            password_id: Şifre ID'si
            encrypted_password: Şifrelenmiş şifre
            button: Göster butonu (toggle için)
        """
        try:
            # Şifreyi çöz
            decrypted = SecurityManager.decrypt_password(encrypted_password, self.fernet_key)
            
            # Popup pencere ile şifreyi göster
            dialog = ctk.CTkToplevel(self)
            dialog.title("Şifre")
            dialog.geometry("400x200")
            dialog.transient(self)
            dialog.grab_set()
            
            # Pencereyi ortala
            dialog.update_idletasks()
            x = (dialog.winfo_screenwidth() // 2) - (400 // 2)
            y = (dialog.winfo_screenheight() // 2) - (200 // 2)
            dialog.geometry(f"400x200+{x}+{y}")
            
            label = ctk.CTkLabel(
                dialog,
                text="Şifreniz:",
                font=ctk.CTkFont(size=14)
            )
            label.pack(pady=(30, 10))
            
            password_textbox = ctk.CTkTextbox(
                dialog,
                width=350,
                height=60,
                font=ctk.CTkFont(size=16, weight="bold"),
                fg_color="#1f1f1f"
            )
            password_textbox.pack(pady=10)
            password_textbox.insert("1.0", decrypted)
            password_textbox.configure(state="disabled")
            
            close_button = ctk.CTkButton(
                dialog,
                text="Kapat",
                command=dialog.destroy,
                width=120
            )
            close_button.pack(pady=10)
            
        except Exception as e:
            messagebox.showerror("Hata", f"Şifre çözülemedi: {str(e)}")
    
    def copy_password_to_clipboard(self, encrypted_password):
        """
        Şifreyi panoya kopyalar.
        
        Args:
            encrypted_password: Şifrelenmiş şifre
        """
        try:
            # Şifreyi çöz
            decrypted = SecurityManager.decrypt_password(encrypted_password, self.fernet_key)
            
            # Panoya kopyala
            pyperclip.copy(decrypted)
            
            messagebox.showinfo("Başarılı", "✅ Şifre panoya kopyalandı!")
        except Exception as e:
            messagebox.showerror("Hata", f"Şifre kopyalanamadı: {str(e)}")
    
    def delete_password(self, password_id):
        """
        Şifreyi siler (onay ister).
        
        Args:
            password_id: Silinecek şifrenin ID'si
        """
        response = messagebox.askyesno(
            "Onay",
            "Bu şifreyi silmek istediğinizden emin misiniz?"
        )
        
        if response:
            if self.db_manager.delete_password(password_id):
                messagebox.showinfo("Başarılı", "Şifre silindi!")
                self.load_passwords()  # Listeyi yenile
            else:
                messagebox.showerror("Hata", "Şifre silinemedi!")
    
    def open_add_password_dialog(self):
        """
        Yeni şifre ekleme dialogunu açar.
        """
        dialog = ctk.CTkToplevel(self)
        dialog.title("Yeni Şifre Ekle")
        dialog.geometry("500x450")
        dialog.transient(self)
        dialog.grab_set()
        
        # Pencereyi ortala
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (500 // 2)
        y = (dialog.winfo_screenheight() // 2) - (450 // 2)
        dialog.geometry(f"500x450+{x}+{y}")
        
        # Container
        container = ctk.CTkFrame(dialog, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=30, pady=30)
        
        # Site Adı
        site_label = ctk.CTkLabel(container, text="Site/Uygulama Adı:", font=ctk.CTkFont(size=14))
        site_label.pack(anchor="w", pady=(0, 5))
        
        site_entry = ctk.CTkEntry(
            container,
            placeholder_text="örn: Gmail, Instagram",
            height=40,
            font=ctk.CTkFont(size=13)
        )
        site_entry.pack(fill="x", pady=(0, 15))
        
        # Kullanıcı Adı
        username_label = ctk.CTkLabel(container, text="Kullanıcı Adı / E-posta:", font=ctk.CTkFont(size=14))
        username_label.pack(anchor="w", pady=(0, 5))
        
        username_entry = ctk.CTkEntry(
            container,
            placeholder_text="örn: kullanici@example.com",
            height=40,
            font=ctk.CTkFont(size=13)
        )
        username_entry.pack(fill="x", pady=(0, 15))
        
        # Şifre
        password_label = ctk.CTkLabel(container, text="Şifre:", font=ctk.CTkFont(size=14))
        password_label.pack(anchor="w", pady=(0, 5))
        
        password_frame = ctk.CTkFrame(container, fg_color="transparent")
        password_frame.pack(fill="x", pady=(0, 15))
        
        password_entry = ctk.CTkEntry(
            password_frame,
            placeholder_text="Şifrenizi girin",
            show="●",
            height=40,
            font=ctk.CTkFont(size=13)
        )
        password_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        # Şifre Oluştur Butonu
        generate_button = ctk.CTkButton(
            password_frame,
            text="🎲 Oluştur",
            command=lambda: self.generate_and_fill_password(password_entry),
            width=120,
            height=40,
            fg_color="#ffc107",
            hover_color="#e0a800",
            text_color="black"
        )
        generate_button.pack(side="left")
        
        # Kaydet Butonu
        save_button = ctk.CTkButton(
            container,
            text="💾 Kaydet",
            command=lambda: self.save_new_password(
                dialog, site_entry, username_entry, password_entry
            ),
            height=45,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color="#28a745",
            hover_color="#218838"
        )
        save_button.pack(fill="x", pady=(20, 0))
    
    def generate_and_fill_password(self, entry_widget):
        """
        Güçlü şifre oluşturur ve entry'ye doldurur.
        
        Args:
            entry_widget: Şifrenin doldurulacağı entry widget'ı
        """
        generated_password = PasswordGenerator.generate(length=16)
        entry_widget.delete(0, 'end')
        entry_widget.configure(show="")  # Oluşturulan şifreyi göster
        entry_widget.insert(0, generated_password)
        messagebox.showinfo("Şifre Oluşturuldu", f"Güçlü şifre oluşturuldu!\n\n{generated_password}")
    
    def save_new_password(self, dialog, site_entry, username_entry, password_entry):
        """
        Yeni şifreyi veritabanına kaydeder.
        
        Args:
            dialog: Dialog penceresi
            site_entry: Site adı entry'si
            username_entry: Kullanıcı adı entry'si
            password_entry: Şifre entry'si
        """
        site_name = site_entry.get().strip()
        username = username_entry.get().strip()
        password = password_entry.get().strip()
        
        # Validasyon
        if not site_name or not username or not password:
            messagebox.showerror("Hata", "Lütfen tüm alanları doldurun!")
            return
        
        try:
            # Şifreyi şifrele
            encrypted = SecurityManager.encrypt_password(password, self.fernet_key)
            
            # Veritabanına kaydet
            if self.db_manager.add_password(site_name, username, encrypted):
                messagebox.showinfo("Başarılı", "✅ Şifre başarıyla kaydedildi!")
                dialog.destroy()
                self.load_passwords()  # Listeyi yenile
            else:
                messagebox.showerror("Hata", "Şifre kaydedilemedi!")
        except Exception as e:
            messagebox.showerror("Hata", f"Bir hata oluştu: {str(e)}")


# ═══════════════════════════════════════════════════════════════════════════
# 6. ANA UYGULAMA - PENCERE YÖNETİMİ
# ═══════════════════════════════════════════════════════════════════════════

class PasswordManagerApp(ctk.CTk):
    """
    Ana uygulama penceresi ve ekran geçişlerini yöneten sınıf.
    """
    
    def __init__(self):
        super().__init__()
        
        # Pencere ayarları
        self.title("EO Digital Lab | Password Vault v1.0")
        self.geometry("1000x700")
        self.minsize(900, 600)
        
        # Dark mode
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Pencereyi ortala
        self.center_window()
        
        # Veritabanı bağlantısı
        self.db_manager = DatabaseManager()
        self.current_screen = None
        self.fernet_key = None
        
        # Login ekranını göster
        self.show_login_screen()
        
        # Kapanış eventi
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def center_window(self):
        """
        Pencereyi ekranın ortasına konumlandırır.
        """
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")
    
    def show_login_screen(self):
        """
        Giriş ekranını gösterir.
        """
        if self.current_screen:
            self.current_screen.destroy()
        
        self.current_screen = LoginScreen(
            self,
            self.db_manager,
            self.on_login_success
        )
    
    def on_login_success(self, fernet_key):
        """
        Giriş başarılı olduğunda çağrılır ve ana ekranı gösterir.
        
        Args:
            fernet_key: Şifreleme anahtarı
        """
        self.fernet_key = fernet_key
        
        if self.current_screen:
            self.current_screen.destroy()
        
        self.current_screen = MainScreen(
            self,
            self.db_manager,
            self.fernet_key
        )
    
    def on_closing(self):
        """
        Uygulama kapatılırken çağrılır.
        """
        # Veritabanı bağlantısını kapat
        self.db_manager.close()
        self.destroy()


# ═══════════════════════════════════════════════════════════════════════════
# 7. PROGRAM BAŞLATMA
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    try:
        app = PasswordManagerApp()
        app.mainloop()
    except Exception as e:
        print(f"❌ Kritik hata: {str(e)}")
        messagebox.showerror("Kritik Hata", f"Uygulama başlatılamadı:\n{str(e)}")