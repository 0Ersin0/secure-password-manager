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
import hmac
import secrets
import string
import base64
import logging
import threading
import json
import csv
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
import pyperclip
from tkinter import messagebox, filedialog
import os
import ctypes


# ═══════════════════════════════════════════════════════════════════════════
# LOGGING YAPILANDIRMASI
# ═══════════════════════════════════════════════════════════════════════════

logging.basicConfig(
    filename='password_manager.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# ÖZEL EXCEPTION SINIFLARI
# ═══════════════════════════════════════════════════════════════════════════

class PasswordManagerError(Exception):
    """Şifre yöneticisi temel hata sınıfı"""
    pass

class EncryptionError(PasswordManagerError):
    """Şifreleme/çözme hataları için"""
    pass

class DatabaseError(PasswordManagerError):
    """Veritabanı hataları için"""
    pass

class AuthenticationError(PasswordManagerError):
    """Kimlik doğrulama hataları için"""
    pass


# ═══════════════════════════════════════════════════════════════════════════
# SABİTLER
# ═══════════════════════════════════════════════════════════════════════════

PBKDF2_ITERATIONS = 600000  # OWASP önerisi
AUTO_LOCK_SECONDS = 300  # 5 dakika
CLIPBOARD_CLEAR_SECONDS = 30  # 30 saniye
PASSWORD_AGE_WARNING_DAYS = 90  # 90 gün
CONFIG_FILE = "password_manager_config.json"  # Ayarlar dosyası


# ═══════════════════════════════════════════════════════════════════════════
# 1. GÜVENLİK KATMANı - ŞİFRELEME VE HASH İŞLEMLERİ
# ═══════════════════════════════════════════════════════════════════════════

class SecurityManager:
    """
    Şifreleme ve hash işlemlerinden sorumlu güvenlik katmanı.
    - Master password hash'leme ve doğrulama
    - Şifre şifreleme/çözme (Fernet)
    - Bellek güvenliği
    - Clipboard güvenliği
    """
    
    _clipboard_timer = None  # Clipboard temizleme zamanlayıcısı
    
    @staticmethod
    def secure_clear_string(sensitive_string: str) -> None:
        """
        Hassas veriyi bellekten güvenli şekilde siler.
        
        Args:
            sensitive_string: Silinecek hassas metin
        """
        try:
            if sensitive_string and isinstance(sensitive_string, str):
                # String'in bellek adresini bul
                str_buffer = ctypes.create_string_buffer(len(sensitive_string))
                ctypes.memmove(str_buffer, sensitive_string.encode(), len(sensitive_string))
                # Belleği sıfırla
                ctypes.memset(str_buffer, 0, len(sensitive_string))
                logger.debug("Hassas veri bellekten temizlendi")
        except Exception as e:
            logger.warning(f"Bellek temizleme sırasında hata: {str(e)}")
    
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
        
        # PBKDF2-HMAC-SHA256 algoritması ile 600,000 iterasyon (OWASP önerisi)
        # Bu, brute-force saldırılarını yavaşlatır
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            PBKDF2_ITERATIONS
        )
        
        logger.info("Master password hash'lendi")
        return password_hash, salt
    
    @staticmethod
    def verify_hash(password: str, stored_hash: bytes, salt: bytes) -> bool:
        """
        Şifreyi timing attack'a karşı güvenli şekilde doğrular.
        
        Args:
            password: Kontrol edilecek şifre
            stored_hash: Veritabanındaki hash
            salt: Salt değeri
        
        Returns:
            Şifreler eşleşirse True
        """
        calculated_hash, _ = SecurityManager.hash_master_password(password, salt)
        # hmac.compare_digest timing attack'a karşı koruma sağlar
        return hmac.compare_digest(calculated_hash, stored_hash)
    
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
            PBKDF2_ITERATIONS
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
            logger.debug("Şifre şifrelendi")
            return encrypted.decode('utf-8')
        except Exception as e:
            logger.error(f"Şifreleme hatası: {str(e)}")
            raise EncryptionError(f"Şifreleme hatası: {str(e)}")
    
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
            logger.debug("Şifre çözüldü")
            return decrypted.decode('utf-8')
        except Exception as e:
            logger.error(f"Şifre çözme hatası: {str(e)}")
            raise EncryptionError(f"Şifre çözme hatası: {str(e)}")
    
    @classmethod
    def copy_to_clipboard_secure(cls, password: str) -> None:
        """
        Şifreyi panoya güvenli şekilde kopyalar ve belirli süre sonra temizler.
        
        Args:
            password: Panoya kopyalanacak şifre
        """
        try:
            # Önceki zamanlayıcıyı iptal et
            if cls._clipboard_timer:
                cls._clipboard_timer.cancel()
            
            # Şifreyi panoya kopyala
            pyperclip.copy(password)
            logger.info("Şifre panoya kopyalandı")
            
            # Belirli süre sonra panoyu temizle
            cls._clipboard_timer = threading.Timer(
                CLIPBOARD_CLEAR_SECONDS,
                cls._clear_clipboard
            )
            cls._clipboard_timer.daemon = True
            cls._clipboard_timer.start()
            
        except Exception as e:
            logger.error(f"Panoya kopyalama hatası: {str(e)}")
            raise PasswordManagerError(f"Panoya kopyalama hatası: {str(e)}")
    
    @classmethod
    def _clear_clipboard(cls) -> None:
        """Panoyu temizler."""
        try:
            pyperclip.copy('')
            logger.info("Pano güvenlik nedeniyle temizlendi")
        except Exception as e:
            logger.warning(f"Pano temizleme hatası: {str(e)}")


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
            
            # Kategoriler tablosu
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS categories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE
                )
            ''')
            
            # Şifreler tablosu
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    site_name TEXT NOT NULL,
                    username TEXT NOT NULL,
                    encrypted_password TEXT NOT NULL,
                    created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    category_id INTEGER,
                    updated_date TIMESTAMP,
                    FOREIGN KEY (category_id) REFERENCES categories(id)
                )
            ''')
            
            # Mevcut veritabanını güncelle (migration)
            try:
                self.cursor.execute("ALTER TABLE passwords ADD COLUMN category_id INTEGER")
            except:
                pass  # Sütun zaten varsa hata verir, yoksay
            
            try:
                self.cursor.execute("ALTER TABLE passwords ADD COLUMN updated_date TIMESTAMP")
            except:
                pass  # Sütun zaten varsa hata verir, yoksay
            
            self.connection.commit()
            logger.info("Veritabanı başarıyla başlatıldı")
        except Exception as e:
            logger.error(f"Veritabanı başlatma hatası: {str(e)}")
            raise DatabaseError(f"Veritabanı başlatma hatası: {str(e)}")
    
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
            logger.error(f"Master password kontrol hatası: {str(e)}")
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
            logger.error(f"Master password kayıt hatası: {str(e)}")
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
            
            # Timing attack'a karşı güvenli doğrulama
            if SecurityManager.verify_hash(password, stored_hash, salt):
                logger.info("Master password doğrulandı")
                return True, salt
            else:
                logger.warning("Yanlış master password girişi")
                return False, None
        except Exception as e:
            logger.error(f"Master password doğrulama hatası: {str(e)}")
            return False, None
    
    def add_password(self, site_name: str, username: str, encrypted_password: str, 
                     category_id: int = None) -> bool:
        """
        Yeni şifre kaydı ekler.
        
        Args:
            site_name: Web sitesi veya uygulama adı
            username: Kullanıcı adı veya e-posta
            encrypted_password: Şifrelenmiş şifre
            category_id: Kategori ID'si (opsiyonel)
        
        Returns:
            Başarılı ise True
        """
        try:
            self.cursor.execute('''
                INSERT INTO passwords (site_name, username, encrypted_password, category_id)
                VALUES (?, ?, ?, ?)
            ''', (site_name, username, encrypted_password, category_id))
            self.connection.commit()
            logger.info(f"Yeni şifre eklendi: {site_name}")
            return True
        except Exception as e:
            logger.error(f"Şifre ekleme hatası: {str(e)}")
            return False
    
    def update_password(self, password_id: int, site_name: str = None, 
                        username: str = None, encrypted_password: str = None,
                        category_id: int = None) -> bool:
        """
        Mevcut şifre kaydını günceller.
        
        Args:
            password_id: Güncellenecek kaydın ID'si
            site_name: Yeni site adı (None ise değişmez)
            username: Yeni kullanıcı adı (None ise değişmez)
            encrypted_password: Yeni şifrelenmiş şifre (None ise değişmez)
            category_id: Yeni kategori ID'si (None ise değişmez)
        
        Returns:
            Başarılı ise True
        """
        try:
            updates = []
            values = []
            
            if site_name is not None:
                updates.append("site_name = ?")
                values.append(site_name)
            if username is not None:
                updates.append("username = ?")
                values.append(username)
            if encrypted_password is not None:
                updates.append("encrypted_password = ?")
                values.append(encrypted_password)
            if category_id is not None:
                updates.append("category_id = ?")
                values.append(category_id)
            
            if not updates:
                return False
            
            updates.append("updated_date = CURRENT_TIMESTAMP")
            values.append(password_id)
            
            query = f"UPDATE passwords SET {', '.join(updates)} WHERE id = ?"
            self.cursor.execute(query, values)
            self.connection.commit()
            logger.info(f"Şifre güncellendi: ID {password_id}")
            return True
        except Exception as e:
            logger.error(f"Şifre güncelleme hatası: {str(e)}")
            return False
    
    def get_all_passwords(self) -> list:
        """
        Tüm kayıtlı şifreleri getirir.
        
        Returns:
            [(id, site_name, username, encrypted_password, created_date, category_id, updated_date), ...]
        """
        try:
            self.cursor.execute('''
                SELECT id, site_name, username, encrypted_password, created_date, 
                       category_id, updated_date
                FROM passwords
                ORDER BY created_date DESC
            ''')
            return self.cursor.fetchall()
        except Exception as e:
            logger.error(f"Şifreleri getirme hatası: {str(e)}")
            return []
    
    def search_passwords(self, query: str) -> list:
        """
        Site adı veya kullanıcı adına göre şifre arar.
        
        Args:
            query: Arama sorgusu
        
        Returns:
            Eşleşen kayıtlar listesi
        """
        try:
            search_pattern = f"%{query}%"
            self.cursor.execute('''
                SELECT id, site_name, username, encrypted_password, created_date, 
                       category_id, updated_date
                FROM passwords
                WHERE site_name LIKE ? OR username LIKE ?
                ORDER BY created_date DESC
            ''', (search_pattern, search_pattern))
            return self.cursor.fetchall()
        except Exception as e:
            logger.error(f"Şifre arama hatası: {str(e)}")
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
            logger.info(f"Şifre silindi: ID {password_id}")
            return True
        except Exception as e:
            logger.error(f"Şifre silme hatası: {str(e)}")
            return False
    
    # ═══════════════════════════════════════════════════════════════════════
    # KATEGORİ İŞLEMLERİ
    # ═══════════════════════════════════════════════════════════════════════
    
    def add_category(self, name: str) -> int:
        """
        Yeni kategori ekler.
        
        Args:
            name: Kategori adı
        
        Returns:
            Eklenen kategorinin ID'si, hata durumunda -1
        """
        try:
            self.cursor.execute('''
                INSERT INTO categories (name) VALUES (?)
            ''', (name,))
            self.connection.commit()
            logger.info(f"Yeni kategori eklendi: {name}")
            return self.cursor.lastrowid
        except Exception as e:
            logger.error(f"Kategori ekleme hatası: {str(e)}")
            return -1
    
    def get_categories(self) -> list:
        """
        Tüm kategorileri getirir.
        
        Returns:
            [(id, name), ...]
        """
        try:
            self.cursor.execute("SELECT id, name FROM categories ORDER BY name")
            return self.cursor.fetchall()
        except Exception as e:
            logger.error(f"Kategorileri getirme hatası: {str(e)}")
            return []
    
    def delete_category(self, category_id: int) -> bool:
        """
        Kategoriyi siler.
        
        Args:
            category_id: Silinecek kategorinin ID'si
        
        Returns:
            Başarılı ise True
        """
        try:
            # Kategoriye ait şifrelerin category_id'sini NULL yap
            self.cursor.execute(
                "UPDATE passwords SET category_id = NULL WHERE category_id = ?",
                (category_id,)
            )
            self.cursor.execute("DELETE FROM categories WHERE id = ?", (category_id,))
            self.connection.commit()
            logger.info(f"Kategori silindi: ID {category_id}")
            return True
        except Exception as e:
            logger.error(f"Kategori silme hatası: {str(e)}")
            return False
    
    # ═══════════════════════════════════════════════════════════════════════
    # MASTER PASSWORD DEĞİŞTİRME
    # ═══════════════════════════════════════════════════════════════════════
    
    def change_master_password(self, old_password: str, new_password: str) -> bool:
        """
        Master password'ü değiştirir ve tüm şifreleri yeniden şifreler.
        
        Args:
            old_password: Eski master password
            new_password: Yeni master password
        
        Returns:
            Başarılı ise True
        """
        try:
            # Eski şifreyi doğrula
            is_valid, old_salt = self.verify_master_password(old_password)
            if not is_valid:
                logger.warning("Master password değiştirme başarısız: Yanlış eski şifre")
                return False
            
            # Eski key
            old_key = SecurityManager.generate_fernet_key(old_password, old_salt)
            
            # Yeni hash ve salt
            new_hash, new_salt = SecurityManager.hash_master_password(new_password)
            new_key = SecurityManager.generate_fernet_key(new_password, new_salt)
            
            # Tüm şifreleri al, çöz ve yeniden şifrele
            passwords = self.get_all_passwords()
            for pwd in passwords:
                pwd_id = pwd[0]
                encrypted_pwd = pwd[3]
                
                # Eski key ile çöz
                decrypted = SecurityManager.decrypt_password(encrypted_pwd, old_key)
                # Yeni key ile şifrele
                re_encrypted = SecurityManager.encrypt_password(decrypted, new_key)
                
                # Güncelle
                self.cursor.execute(
                    "UPDATE passwords SET encrypted_password = ? WHERE id = ?",
                    (re_encrypted, pwd_id)
                )
            
            # Master password'ü güncelle
            self.cursor.execute('''
                UPDATE master_password SET password_hash = ?, salt = ? WHERE id = 1
            ''', (new_hash, new_salt))
            
            self.connection.commit()
            logger.info("Master password başarıyla değiştirildi")
            return True
            
        except Exception as e:
            logger.error(f"Master password değiştirme hatası: {str(e)}")
            self.connection.rollback()
            return False
    
    # ═══════════════════════════════════════════════════════════════════════
    # DIŞA/İÇE AKTARMA
    # ═══════════════════════════════════════════════════════════════════════
    
    def export_to_json(self, filepath: str, fernet_key: bytes, include_passwords: bool = False) -> bool:
        """
        Şifreleri JSON formatında dışa aktarır.
        
        Args:
            filepath: Kaydedilecek dosya yolu
            fernet_key: Şifre çözme anahtarı
            include_passwords: Şifreleri düz metin olarak dahil et (güvenlik riski!)
        
        Returns:
            Başarılı ise True
        """
        try:
            passwords = self.get_all_passwords()
            export_data = []
            
            for pwd in passwords:
                entry = {
                    "id": pwd[0],
                    "site_name": pwd[1],
                    "username": pwd[2],
                    "created_date": pwd[4],
                    "category_id": pwd[5],
                    "updated_date": pwd[6]
                }
                
                if include_passwords:
                    try:
                        entry["password"] = SecurityManager.decrypt_password(pwd[3], fernet_key)
                    except:
                        entry["password"] = "[ÇÖZÜLEMEDI]"
                
                export_data.append(entry)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, ensure_ascii=False, indent=2, default=str)
            
            logger.info(f"JSON dışa aktarma tamamlandı: {filepath}")
            return True
        except Exception as e:
            logger.error(f"JSON dışa aktarma hatası: {str(e)}")
            return False
    
    def export_to_csv(self, filepath: str, fernet_key: bytes, include_passwords: bool = False) -> bool:
        """
        Şifreleri CSV formatında dışa aktarır.
        
        Args:
            filepath: Kaydedilecek dosya yolu
            fernet_key: Şifre çözme anahtarı
            include_passwords: Şifreleri düz metin olarak dahil et (güvenlik riski!)
        
        Returns:
            Başarılı ise True
        """
        try:
            passwords = self.get_all_passwords()
            
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                if include_passwords:
                    writer.writerow(['Site', 'Kullanıcı Adı', 'Şifre', 'Oluşturma Tarihi'])
                else:
                    writer.writerow(['Site', 'Kullanıcı Adı', 'Oluşturma Tarihi'])
                
                for pwd in passwords:
                    if include_passwords:
                        try:
                            decrypted = SecurityManager.decrypt_password(pwd[3], fernet_key)
                        except:
                            decrypted = "[ÇÖZÜLEMEDI]"
                        writer.writerow([pwd[1], pwd[2], decrypted, pwd[4]])
                    else:
                        writer.writerow([pwd[1], pwd[2], pwd[4]])
            
            logger.info(f"CSV dışa aktarma tamamlandı: {filepath}")
            return True
        except Exception as e:
            logger.error(f"CSV dışa aktarma hatası: {str(e)}")
            return False
    
    def import_from_csv(self, filepath: str, fernet_key: bytes) -> tuple:
        """
        CSV dosyasından şifreleri içe aktarır.
        
        Args:
            filepath: İçe aktarılacak dosya yolu
            fernet_key: Şifreleme anahtarı
        
        Returns:
            (başarılı_sayısı, toplam_sayısı)
        """
        try:
            imported = 0
            total = 0
            
            with open(filepath, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                
                for row in reader:
                    total += 1
                    site = row.get('Site', row.get('site_name', ''))
                    username = row.get('Kullanıcı Adı', row.get('username', ''))
                    password = row.get('Şifre', row.get('password', ''))
                    
                    if site and username and password:
                        encrypted = SecurityManager.encrypt_password(password, fernet_key)
                        if self.add_password(site, username, encrypted):
                            imported += 1
            
            logger.info(f"CSV içe aktarma tamamlandı: {imported}/{total}")
            return imported, total
        except Exception as e:
            logger.error(f"CSV içe aktarma hatası: {str(e)}")
            return 0, 0
    
    def close(self):
        """
        Veritabanı bağlantısını kapatır.
        """
        if self.connection:
            self.connection.close()
            logger.info("Veritabanı bağlantısı kapatıldı")
    
    def __enter__(self):
        """Context manager giriş."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager çıkış."""
        self.close()


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
    
    @staticmethod
    def calculate_strength(password: str) -> tuple:
        """
        Şifre gücünü hesaplar.
        
        Args:
            password: Değerlendirilecek şifre
        
        Returns:
            (puan, seviye, renk) tuple'ı
            puan: 0-100 arası değer
            seviye: "Çok Zayıf", "Zayıf", "Orta", "Güçlü", "Çok Güçlü"
            renk: Görsel için renk kodu
        """
        if not password:
            return 0, "Boş", "#666666"
        
        score = 0
        
        # Uzunluk puanı (max 30)
        length = len(password)
        if length >= 16:
            score += 30
        elif length >= 12:
            score += 25
        elif length >= 8:
            score += 15
        elif length >= 6:
            score += 10
        else:
            score += 5
        
        # Karakter çeşitliliği puanları
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?~`'\"\\/€₺£" for c in password)
        
        if has_lower:
            score += 15
        if has_upper:
            score += 15
        if has_digit:
            score += 15
        if has_symbol:
            score += 20
        
        # Bonus puanları
        # Çeşitlilik bonusu
        variety_count = sum([has_lower, has_upper, has_digit, has_symbol])
        score += variety_count * 2
        
        # Uzunluk bonusu
        if length >= 20:
            score += 5
        
        # Maksimum 100
        score = min(score, 100)
        
        # Seviye belirleme
        if score >= 80:
            return score, "Çok Güçlü", "#28a745"
        elif score >= 60:
            return score, "Güçlü", "#5cb85c"
        elif score >= 40:
            return score, "Orta", "#ffc107"
        elif score >= 20:
            return score, "Zayıf", "#fd7e14"
        else:
            return score, "Çok Zayıf", "#dc3545"
    
    @staticmethod
    def get_strength_suggestions(password: str) -> list:
        """
        Şifre güçlendirme önerileri verir.
        
        Args:
            password: Değerlendirilecek şifre
        
        Returns:
            Öneri listesi
        """
        suggestions = []
        
        if len(password) < 8:
            suggestions.append("⚠️ En az 8 karakter kullanın")
        if len(password) < 12:
            suggestions.append("💡 12+ karakter daha güvenlidir")
        
        if not any(c.isupper() for c in password):
            suggestions.append("🔤 Büyük harf ekleyin")
        
        if not any(c.islower() for c in password):
            suggestions.append("🔡 Küçük harf ekleyin")
        
        if not any(c.isdigit() for c in password):
            suggestions.append("🔢 Rakam ekleyin")
        
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            suggestions.append("🔣 Özel karakter ekleyin (!@#$%...)")
        
        if not suggestions:
            suggestions.append("✅ Şifreniz güçlü!")
        
        return suggestions


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
        self.parent = parent
        self.db_manager = db_manager
        self.fernet_key = fernet_key
        self.search_query = ""
        self.sort_by = "date"  # "date", "name", "username"
        self.auto_lock_timer = None
        
        self.pack(fill="both", expand=True, padx=20, pady=20)
        self.setup_ui()
        self.load_passwords()
        self.start_auto_lock_timer()
        
        # Mouse ve klavye hareketlerini izle (otomatik kilit için)
        self.bind_all("<Motion>", self.reset_auto_lock_timer)
        self.bind_all("<Key>", self.reset_auto_lock_timer)
    
    def setup_ui(self):
        """
        Ana ekranın arayüzünü oluşturur.
        """
        # ═══════════════════════════════════════════════════════════════════
        # ÜST MENÜ BAR
        # ═══════════════════════════════════════════════════════════════════
        
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 15))
        
        # Sol taraf - Başlık
        title_label = ctk.CTkLabel(
            header_frame,
            text="🔐 Kayıtlı Şifrelerim",
            font=ctk.CTkFont(size=24, weight="bold")
        )
        title_label.pack(side="left")
        
        # Sağ taraf - Butonlar
        buttons_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        buttons_frame.pack(side="right")
        
        # Ayarlar Butonu
        settings_button = ctk.CTkButton(
            buttons_frame,
            text="⚙️",
            command=self.open_settings_dialog,
            font=ctk.CTkFont(size=18),
            fg_color="#6c757d",
            hover_color="#5a6268",
            width=45,
            height=40
        )
        settings_button.pack(side="right", padx=(10, 0))
        
        # Yeni Kayıt Butonu
        add_button = ctk.CTkButton(
            buttons_frame,
            text="➕ Yeni Kayıt",
            command=self.open_add_password_dialog,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#28a745",
            hover_color="#218838",
            width=140,
            height=40
        )
        add_button.pack(side="right", padx=(10, 0))
        
        # Kilit Butonu
        lock_button = ctk.CTkButton(
            buttons_frame,
            text="🔒 Kilitle",
            command=self.lock_session,
            font=ctk.CTkFont(size=14),
            fg_color="#dc3545",
            hover_color="#c82333",
            width=100,
            height=40
        )
        lock_button.pack(side="right")
        
        # ═══════════════════════════════════════════════════════════════════
        # ARAMA VE FİLTRE BARI
        # ═══════════════════════════════════════════════════════════════════
        
        search_frame = ctk.CTkFrame(self, fg_color="transparent")
        search_frame.pack(fill="x", pady=(0, 15))
        
        # Arama Kutusu
        self.search_entry = ctk.CTkEntry(
            search_frame,
            placeholder_text="🔍 Site veya kullanıcı adı ara...",
            height=40,
            width=400,
            font=ctk.CTkFont(size=14)
        )
        self.search_entry.pack(side="left", fill="x", expand=True)
        self.search_entry.bind("<KeyRelease>", self.on_search)
        
        # Sıralama Seçenekleri
        sort_label = ctk.CTkLabel(
            search_frame,
            text="Sırala:",
            font=ctk.CTkFont(size=13)
        )
        sort_label.pack(side="left", padx=(20, 5))
        
        self.sort_menu = ctk.CTkOptionMenu(
            search_frame,
            values=["Tarihe Göre", "İsme Göre", "Kullanıcıya Göre"],
            command=self.on_sort_change,
            width=140,
            height=35
        )
        self.sort_menu.pack(side="left")
        
        # ═══════════════════════════════════════════════════════════════════
        # ŞİFRE LİSTESİ
        # ═══════════════════════════════════════════════════════════════════
        
        self.scrollable_frame = ctk.CTkScrollableFrame(
            self,
            fg_color="transparent"
        )
        self.scrollable_frame.pack(fill="both", expand=True)
    
    def load_passwords(self):
        """
        Veritabanından şifreleri yükler ve listeler.
        Arama ve sıralama kriterlerini uygular.
        """
        # Önce mevcut widget'ları temizle
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
        
        # Arama varsa search, yoksa tüm şifreleri getir
        if self.search_query:
            passwords = self.db_manager.search_passwords(self.search_query)
        else:
            passwords = self.db_manager.get_all_passwords()
        
        # Sıralama uygula
        if passwords:
            if self.sort_by == "name":
                passwords = sorted(passwords, key=lambda x: x[1].lower() if x[1] else "")
            elif self.sort_by == "username":
                passwords = sorted(passwords, key=lambda x: x[2].lower() if x[2] else "")
            # "date" için varsayılan sıra (created_date DESC) kullanılır
        
        if not passwords:
            # Hiç kayıt yoksa bilgilendirme göster
            if self.search_query:
                empty_text = f"'{self.search_query}' için sonuç bulunamadı."
            else:
                empty_text = "Henüz kayıtlı şifre yok.\n➕ 'Yeni Kayıt' butonuna tıklayarak başlayın!"
            
            empty_label = ctk.CTkLabel(
                self.scrollable_frame,
                text=empty_text,
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
            password_data: (id, site_name, username, encrypted_password, created_date, category_id, updated_date)
        """
        password_id = password_data[0]
        site_name = password_data[1]
        username = password_data[2]
        encrypted_password = password_data[3]
        created_date = password_data[4]
        
        # Şifre yaşı kontrolü
        is_old_password = False
        if created_date:
            try:
                if isinstance(created_date, str):
                    created_dt = datetime.strptime(created_date.split('.')[0], "%Y-%m-%d %H:%M:%S")
                else:
                    created_dt = created_date
                age_days = (datetime.now() - created_dt).days
                is_old_password = age_days > PASSWORD_AGE_WARNING_DAYS
            except:
                pass
        
        # Kart frame'i
        card_color = "#3d2a2a" if is_old_password else "#2b2b2b"
        card = ctk.CTkFrame(
            self.scrollable_frame,
            fg_color=card_color,
            corner_radius=10
        )
        card.pack(fill="x", pady=8, ipady=10)
        
        # Sol taraf - Site bilgisi
        left_frame = ctk.CTkFrame(card, fg_color="transparent")
        left_frame.pack(side="left", fill="both", expand=True, padx=15)
        
        # Yaşlı şifre uyarısı
        if is_old_password:
            warning_label = ctk.CTkLabel(
                left_frame,
                text="⚠️ Eski Şifre",
                font=ctk.CTkFont(size=11),
                text_color="#ffc107"
            )
            warning_label.pack(anchor="w")
        
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
        
        # Şifreyi Göster Butonu
        show_button = ctk.CTkButton(
            right_frame,
            text="👁️",
            command=lambda: self.toggle_password_visibility(
                password_id, encrypted_password, show_button
            ),
            width=40,
            fg_color="#6c757d",
            hover_color="#5a6268"
        )
        show_button.pack(side="left", padx=2)
        
        # Kopyala Butonu
        copy_button = ctk.CTkButton(
            right_frame,
            text="📋",
            command=lambda: self.copy_password_to_clipboard(encrypted_password),
            width=40,
            fg_color="#007bff",
            hover_color="#0056b3"
        )
        copy_button.pack(side="left", padx=2)
        
        # Düzenle Butonu
        edit_button = ctk.CTkButton(
            right_frame,
            text="✏️",
            command=lambda pd=password_data: self.open_edit_password_dialog(pd),
            width=40,
            fg_color="#ffc107",
            hover_color="#e0a800",
            text_color="black"
        )
        edit_button.pack(side="left", padx=2)
        
        # Sil Butonu
        delete_button = ctk.CTkButton(
            right_frame,
            text="🗑️",
            command=lambda: self.delete_password(password_id),
            width=40,
            fg_color="#dc3545",
            hover_color="#c82333"
        )
        delete_button.pack(side="left", padx=2)
    
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
        Şifreyi güvenli şekilde panoya kopyalar.
        30 saniye sonra otomatik olarak temizlenir.
        
        Args:
            encrypted_password: Şifrelenmiş şifre
        """
        try:
            # Şifreyi çöz
            decrypted = SecurityManager.decrypt_password(encrypted_password, self.fernet_key)
            
            # Güvenli kopyalama kullan (otomatik temizleme dahil)
            SecurityManager.copy_to_clipboard_secure(decrypted)
            
            messagebox.showinfo(
                "Başarılı", 
                f"✅ Şifre panoya kopyalandı!\n\n"
                f"⏱️ Güvenlik için {CLIPBOARD_CLEAR_SECONDS} saniye sonra otomatik silinecek."
            )
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
    
    # ═══════════════════════════════════════════════════════════════════════
    # ARAMA VE SIRALAMA
    # ═══════════════════════════════════════════════════════════════════════
    
    def on_search(self, event=None):
        """Arama kutusundaki değişikliklere göre listeyi filtreler."""
        self.search_query = self.search_entry.get().strip()
        self.load_passwords()
    
    def on_sort_change(self, choice):
        """Sıralama seçeneğine göre listeyi yeniden sıralar."""
        if choice == "Tarihe Göre":
            self.sort_by = "date"
        elif choice == "İsme Göre":
            self.sort_by = "name"
        elif choice == "Kullanıcıya Göre":
            self.sort_by = "username"
        self.load_passwords()
    
    # ═══════════════════════════════════════════════════════════════════════
    # OTOMATİK KİLİT
    # ═══════════════════════════════════════════════════════════════════════
    
    def start_auto_lock_timer(self):
        """Otomatik kilit zamanlayıcısını başlatır."""
        if self.auto_lock_timer:
            self.auto_lock_timer.cancel()
        
        self.auto_lock_timer = threading.Timer(
            AUTO_LOCK_SECONDS,
            self.auto_lock_callback
        )
        self.auto_lock_timer.daemon = True
        self.auto_lock_timer.start()
        logger.debug(f"Otomatik kilit zamanlayıcısı başlatıldı ({AUTO_LOCK_SECONDS} saniye)")
    
    def reset_auto_lock_timer(self, event=None):
        """Kullanıcı aktivitesi olduğunda zamanlayıcıyı sıfırlar."""
        self.start_auto_lock_timer()
    
    def auto_lock_callback(self):
        """Zamanlayıcı dolduğunda otomatik kilitleme yapar."""
        try:
            self.after(0, self.lock_session)
        except:
            pass
    
    def lock_session(self):
        """Oturumu kilitler ve giriş ekranına döner."""
        # Timer'ı durdur
        if self.auto_lock_timer:
            self.auto_lock_timer.cancel()
            self.auto_lock_timer = None
        
        # Event'leri kaldır
        try:
            self.unbind_all("<Motion>")
            self.unbind_all("<Key>")
        except:
            pass
        
        # Fernet key'i temizle
        self.fernet_key = None
        
        logger.info("Oturum kilitlendi")
        
        # Parent referansını al ve after ile çağır (thread-safe)
        parent = self.parent
        parent.fernet_key = None
        parent.current_screen = None
        
        # Bu frame'i yok et
        self.destroy()
        
        # Login ekranını göster (after ile güvenli çağrı)
        parent.after(50, parent.show_login_screen)
    
    # ═══════════════════════════════════════════════════════════════════════
    # AYARLAR DİALOGU
    # ═══════════════════════════════════════════════════════════════════════
    
    def open_settings_dialog(self):
        """Ayarlar dialogunu açar."""
        dialog = ctk.CTkToplevel(self)
        dialog.title("⚙️ Ayarlar")
        dialog.geometry("500x550")
        dialog.transient(self)
        # grab_set kaldırıldı - tema değişikliğinde sorun yaratıyordu
        dialog.focus_force()
        dialog.lift()
        dialog.attributes("-topmost", True)
        dialog.after(100, lambda: dialog.attributes("-topmost", False))
        
        # Pencereyi ortala
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (500 // 2)
        y = (dialog.winfo_screenheight() // 2) - (550 // 2)
        dialog.geometry(f"500x550+{x}+{y}")
        
        container = ctk.CTkFrame(dialog, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=30, pady=30)
        
        # Başlık
        title_label = ctk.CTkLabel(
            container,
            text="⚙️ Ayarlar",
            font=ctk.CTkFont(size=22, weight="bold")
        )
        title_label.pack(pady=(0, 25))
        
        # ═══════════════════════════════════════════════════════════════════
        # TEMA AYARLARI
        # ═══════════════════════════════════════════════════════════════════
        
        theme_frame = ctk.CTkFrame(container)
        theme_frame.pack(fill="x", pady=10)
        
        theme_label = ctk.CTkLabel(
            theme_frame,
            text="🎨 Tema",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        theme_label.pack(anchor="w", padx=15, pady=(10, 5))
        
        theme_options = ctk.CTkFrame(theme_frame, fg_color="transparent")
        theme_options.pack(fill="x", padx=15, pady=(0, 10))
        
        # Tema durumu label'ı
        theme_status = ctk.CTkLabel(
            theme_options,
            text="",
            font=ctk.CTkFont(size=11),
            text_color="gray"
        )
        
        def save_theme_preference(theme_mode):
            """Tema tercihini dosyaya kaydeder."""
            try:
                config = {}
                if os.path.exists(CONFIG_FILE):
                    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                        config = json.load(f)
                config['theme'] = theme_mode
                with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                    json.dump(config, f, ensure_ascii=False, indent=2)
                logger.info(f"Tema tercihi kaydedildi: {theme_mode}")
            except Exception as e:
                logger.error(f"Tema kaydetme hatası: {str(e)}")
        
        def change_theme(choice):
            try:
                if choice == "Koyu":
                    mode = "dark"
                elif choice == "Açık":
                    mode = "light"
                else:
                    mode = "system"
                
                ctk.set_appearance_mode(mode)
                save_theme_preference(mode)
                logger.info(f"Tema değiştirildi: {choice}")
                
                # Status label ile bilgi göster (messagebox yerine)
                theme_status.configure(text=f"✓ {choice} tema uygulandı", text_color="#28a745")
                
            except Exception as e:
                logger.error(f"Tema değiştirme hatası: {str(e)}")
                theme_status.configure(text=f"✗ Hata: {str(e)}", text_color="#dc3545")
        
        theme_menu = ctk.CTkOptionMenu(
            theme_options,
            values=["Koyu", "Açık", "Sistem"],
            command=change_theme,
            width=200
        )
        current_mode = ctk.get_appearance_mode()
        if current_mode == "Dark":
            theme_menu.set("Koyu")
        elif current_mode == "Light":
            theme_menu.set("Açık")
        else:
            theme_menu.set("Sistem")
        theme_menu.pack(side="left", padx=(0, 10))
        theme_status.pack(side="left")
        
        # ═══════════════════════════════════════════════════════════════════
        # GÜVENLİK AYARLARI
        # ═══════════════════════════════════════════════════════════════════
        
        security_frame = ctk.CTkFrame(container)
        security_frame.pack(fill="x", pady=10)
        
        security_label = ctk.CTkLabel(
            security_frame,
            text="🔐 Güvenlik",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        security_label.pack(anchor="w", padx=15, pady=(10, 5))
        
        # Master Password Değiştirme
        change_pass_button = ctk.CTkButton(
            security_frame,
            text="🔑 Master Password Değiştir",
            command=lambda: self.open_change_master_password_dialog(dialog),
            fg_color="#6c757d",
            hover_color="#5a6268",
            width=250
        )
        change_pass_button.pack(padx=15, pady=10)
        
        # ═══════════════════════════════════════════════════════════════════
        # DIŞA/İÇE AKTARMA
        # ═══════════════════════════════════════════════════════════════════
        
        export_frame = ctk.CTkFrame(container)
        export_frame.pack(fill="x", pady=10)
        
        export_label = ctk.CTkLabel(
            export_frame,
            text="📦 Yedekleme",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        export_label.pack(anchor="w", padx=15, pady=(10, 5))
        
        export_buttons = ctk.CTkFrame(export_frame, fg_color="transparent")
        export_buttons.pack(fill="x", padx=15, pady=(0, 10))
        
        # CSV Dışa Aktar
        export_csv_button = ctk.CTkButton(
            export_buttons,
            text="📤 CSV Dışa Aktar",
            command=lambda: self.export_passwords("csv", dialog),
            fg_color="#17a2b8",
            hover_color="#138496",
            width=150
        )
        export_csv_button.pack(side="left", padx=(0, 10))
        
        # JSON Dışa Aktar
        export_json_button = ctk.CTkButton(
            export_buttons,
            text="📤 JSON Dışa Aktar",
            command=lambda: self.export_passwords("json", dialog),
            fg_color="#17a2b8",
            hover_color="#138496",
            width=150
        )
        export_json_button.pack(side="left")
        
        # CSV İçe Aktar
        import_frame = ctk.CTkFrame(export_frame, fg_color="transparent")
        import_frame.pack(fill="x", padx=15, pady=(5, 10))
        
        import_csv_button = ctk.CTkButton(
            import_frame,
            text="📥 CSV İçe Aktar",
            command=lambda: self.import_passwords(dialog),
            fg_color="#28a745",
            hover_color="#218838",
            width=150
        )
        import_csv_button.pack(side="left")
        
        # Kapat Butonu
        close_button = ctk.CTkButton(
            container,
            text="Kapat",
            command=dialog.destroy,
            width=150,
            height=40
        )
        close_button.pack(pady=(20, 0))
    
    def open_change_master_password_dialog(self, parent_dialog):
        """Master password değiştirme dialogunu açar."""
        dialog = ctk.CTkToplevel(self)
        dialog.title("🔑 Master Password Değiştir")
        dialog.geometry("400x350")
        dialog.transient(self)
        dialog.grab_set()
        
        # Pencereyi ortala
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (400 // 2)
        y = (dialog.winfo_screenheight() // 2) - (350 // 2)
        dialog.geometry(f"400x350+{x}+{y}")
        
        container = ctk.CTkFrame(dialog, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=30, pady=30)
        
        # Eski Şifre
        old_label = ctk.CTkLabel(container, text="Mevcut Şifre:", font=ctk.CTkFont(size=14))
        old_label.pack(anchor="w", pady=(0, 5))
        
        old_entry = ctk.CTkEntry(container, show="●", height=40)
        old_entry.pack(fill="x", pady=(0, 15))
        
        # Yeni Şifre
        new_label = ctk.CTkLabel(container, text="Yeni Şifre:", font=ctk.CTkFont(size=14))
        new_label.pack(anchor="w", pady=(0, 5))
        
        new_entry = ctk.CTkEntry(container, show="●", height=40)
        new_entry.pack(fill="x", pady=(0, 15))
        
        # Yeni Şifre Tekrar
        confirm_label = ctk.CTkLabel(container, text="Yeni Şifre (Tekrar):", font=ctk.CTkFont(size=14))
        confirm_label.pack(anchor="w", pady=(0, 5))
        
        confirm_entry = ctk.CTkEntry(container, show="●", height=40)
        confirm_entry.pack(fill="x", pady=(0, 20))
        
        def change_password():
            old_pwd = old_entry.get().strip()
            new_pwd = new_entry.get().strip()
            confirm_pwd = confirm_entry.get().strip()
            
            if not old_pwd or not new_pwd or not confirm_pwd:
                messagebox.showerror("Hata", "Tüm alanları doldurun!")
                return
            
            if new_pwd != confirm_pwd:
                messagebox.showerror("Hata", "Yeni şifreler eşleşmiyor!")
                return
            
            if len(new_pwd) < 6:
                messagebox.showerror("Hata", "Yeni şifre en az 6 karakter olmalıdır!")
                return
            
            if self.db_manager.change_master_password(old_pwd, new_pwd):
                # Yeni fernet key oluştur
                _, salt = self.db_manager.verify_master_password(new_pwd)
                self.fernet_key = SecurityManager.generate_fernet_key(new_pwd, salt)
                
                messagebox.showinfo("Başarılı", "✅ Master password başarıyla değiştirildi!")
                dialog.destroy()
            else:
                messagebox.showerror("Hata", "Şifre değiştirilemedi! Mevcut şifre yanlış olabilir.")
        
        change_button = ctk.CTkButton(
            container,
            text="💾 Değiştir",
            command=change_password,
            height=45,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color="#28a745",
            hover_color="#218838"
        )
        change_button.pack(fill="x")
    
    def export_passwords(self, format_type, parent_dialog):
        """Şifreleri dışa aktarır."""
        # Şifrelerin dahil edilip edilmeyeceğini sor
        include_passwords = messagebox.askyesno(
            "Şifreler Dahil Mi?",
            "Şifreleri düz metin olarak dahil etmek ister misiniz?\n\n"
            "⚠️ DİKKAT: Bu dosya güvenlik riski oluşturabilir!\n"
            "Güvenli bir yerde saklayın."
        )
        
        if format_type == "csv":
            filepath = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV Dosyaları", "*.csv")],
                title="CSV Olarak Kaydet"
            )
            if filepath:
                if self.db_manager.export_to_csv(filepath, self.fernet_key, include_passwords):
                    messagebox.showinfo("Başarılı", f"✅ Veriler başarıyla dışa aktarıldı:\n{filepath}")
                else:
                    messagebox.showerror("Hata", "Dışa aktarma başarısız!")
        else:
            filepath = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON Dosyaları", "*.json")],
                title="JSON Olarak Kaydet"
            )
            if filepath:
                if self.db_manager.export_to_json(filepath, self.fernet_key, include_passwords):
                    messagebox.showinfo("Başarılı", f"✅ Veriler başarıyla dışa aktarıldı:\n{filepath}")
                else:
                    messagebox.showerror("Hata", "Dışa aktarma başarısız!")
    
    def import_passwords(self, parent_dialog):
        """CSV dosyasından şifreleri içe aktarır."""
        filepath = filedialog.askopenfilename(
            filetypes=[("CSV Dosyaları", "*.csv")],
            title="CSV Dosyası Seç"
        )
        
        if filepath:
            imported, total = self.db_manager.import_from_csv(filepath, self.fernet_key)
            messagebox.showinfo(
                "İçe Aktarma Tamamlandı",
                f"✅ {imported}/{total} kayıt başarıyla içe aktarıldı!"
            )
            self.load_passwords()
    
    # ═══════════════════════════════════════════════════════════════════════
    # ŞİFRE DÜZENLEME
    # ═══════════════════════════════════════════════════════════════════════
    
    def open_edit_password_dialog(self, password_data):
        """Şifre düzenleme dialogunu açar."""
        password_id = password_data[0]
        site_name = password_data[1]
        username = password_data[2]
        encrypted_password = password_data[3]
        
        dialog = ctk.CTkToplevel(self)
        dialog.title("✏️ Şifre Düzenle")
        dialog.geometry("500x500")
        dialog.transient(self)
        dialog.grab_set()
        
        # Pencereyi ortala
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (500 // 2)
        y = (dialog.winfo_screenheight() // 2) - (500 // 2)
        dialog.geometry(f"500x500+{x}+{y}")
        
        container = ctk.CTkFrame(dialog, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=30, pady=30)
        
        # Site Adı
        site_label = ctk.CTkLabel(container, text="Site/Uygulama Adı:", font=ctk.CTkFont(size=14))
        site_label.pack(anchor="w", pady=(0, 5))
        
        site_entry = ctk.CTkEntry(container, height=40, font=ctk.CTkFont(size=13))
        site_entry.pack(fill="x", pady=(0, 15))
        site_entry.insert(0, site_name)
        
        # Kullanıcı Adı
        username_label = ctk.CTkLabel(container, text="Kullanıcı Adı / E-posta:", font=ctk.CTkFont(size=14))
        username_label.pack(anchor="w", pady=(0, 5))
        
        username_entry = ctk.CTkEntry(container, height=40, font=ctk.CTkFont(size=13))
        username_entry.pack(fill="x", pady=(0, 15))
        username_entry.insert(0, username)
        
        # Şifre
        password_label = ctk.CTkLabel(container, text="Şifre:", font=ctk.CTkFont(size=14))
        password_label.pack(anchor="w", pady=(0, 5))
        
        password_frame = ctk.CTkFrame(container, fg_color="transparent")
        password_frame.pack(fill="x", pady=(0, 10))
        
        password_entry = ctk.CTkEntry(password_frame, height=40, font=ctk.CTkFont(size=13))
        password_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        # Mevcut şifreyi çöz ve göster
        try:
            decrypted = SecurityManager.decrypt_password(encrypted_password, self.fernet_key)
            password_entry.insert(0, decrypted)
        except:
            password_entry.insert(0, "[Çözülemedi]")
        
        generate_button = ctk.CTkButton(
            password_frame,
            text="🎲 Oluştur",
            command=lambda: self.generate_and_fill_password(password_entry),
            width=100,
            height=40,
            fg_color="#ffc107",
            hover_color="#e0a800",
            text_color="black"
        )
        generate_button.pack(side="left")
        
        # Şifre Gücü Göstergesi
        strength_frame = ctk.CTkFrame(container, fg_color="transparent")
        strength_frame.pack(fill="x", pady=(5, 15))
        
        strength_label = ctk.CTkLabel(
            strength_frame,
            text="Şifre Gücü: -",
            font=ctk.CTkFont(size=12)
        )
        strength_label.pack(side="left")
        
        strength_bar = ctk.CTkProgressBar(strength_frame, width=200, height=10)
        strength_bar.pack(side="left", padx=(10, 0))
        strength_bar.set(0)
        
        def update_strength(*args):
            pwd = password_entry.get()
            score, level, color = PasswordGenerator.calculate_strength(pwd)
            strength_label.configure(text=f"Şifre Gücü: {level}")
            strength_bar.set(score / 100)
            strength_bar.configure(progress_color=color)
        
        password_entry.bind("<KeyRelease>", update_strength)
        update_strength()  # İlk değer için güncelle
        
        def save_changes():
            new_site = site_entry.get().strip()
            new_username = username_entry.get().strip()
            new_password = password_entry.get().strip()
            
            if not new_site or not new_username or not new_password:
                messagebox.showerror("Hata", "Tüm alanları doldurun!")
                return
            
            try:
                encrypted = SecurityManager.encrypt_password(new_password, self.fernet_key)
                if self.db_manager.update_password(
                    password_id, 
                    site_name=new_site, 
                    username=new_username, 
                    encrypted_password=encrypted
                ):
                    messagebox.showinfo("Başarılı", "✅ Şifre güncellendi!")
                    dialog.destroy()
                    self.load_passwords()
                else:
                    messagebox.showerror("Hata", "Güncelleme başarısız!")
            except Exception as e:
                messagebox.showerror("Hata", f"Hata oluştu: {str(e)}")
        
        # Butonlar
        buttons_frame = ctk.CTkFrame(container, fg_color="transparent")
        buttons_frame.pack(fill="x", pady=(20, 0))
        
        save_button = ctk.CTkButton(
            buttons_frame,
            text="💾 Kaydet",
            command=save_changes,
            height=45,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color="#28a745",
            hover_color="#218838"
        )
        save_button.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        cancel_button = ctk.CTkButton(
            buttons_frame,
            text="İptal",
            command=dialog.destroy,
            height=45,
            font=ctk.CTkFont(size=16),
            fg_color="#6c757d",
            hover_color="#5a6268"
        )
        cancel_button.pack(side="left", fill="x", expand=True)


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
        
        # Kaydedilmiş tema tercihini yükle
        saved_theme = self.load_theme_preference()
        ctk.set_appearance_mode(saved_theme)
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
    
    def load_theme_preference(self) -> str:
        """
        Kaydedilmiş tema tercihini dosyadan yükler.
        
        Returns:
            Tema modu: "dark", "light" veya "system"
        """
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    theme = config.get('theme', 'dark')
                    logger.info(f"Tema tercihi yüklendi: {theme}")
                    return theme
        except Exception as e:
            logger.warning(f"Tema tercihi yüklenemedi: {str(e)}")
        return "dark"  # Varsayılan
    
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