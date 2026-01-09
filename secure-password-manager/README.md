# 🛡️ EO Digital Vault v2.0 | Enterprise Password Manager

> **"Güvenlik bir ürün değil, bir süreçtir."**

**EO Digital Vault**, verilerinizi 3. parti bulut sunucularında değil, kendi bilgisayarınızda en üst düzey güvenlik standartlarıyla şifreleyerek saklayan, yerel (offline) ve kurumsal seviyede bir parola yönetim aracıdır.

Bu proje **EO Digital Lab** siber güvenlik çalışmaları kapsamında, **Blue Team (Savunma)** prensiplerine göre geliştirilmiştir.

## 🚀 v2.0 Sürüm Notları (Major Update)
Bu sürümle birlikte uygulama, basit bir şifre saklayıcıdan **Kurumsal Güvenlik Mimarisine** geçiş yapmıştır.

| Özellik | Açıklama |
| :--- | :--- |
| 🛡️ **Gelişmiş Güvenlik** | Timing Attack koruması ve OWASP standartlarında 600.000 iterasyon. |
| 🧹 **Bellek Hijyeni** | Hassas veriler (RAM) bellekten ve panodan (30 sn) otomatik temizlenir. |
| 📝 **Audit Logging** | Tüm güvenlik olayları ve hatalar `password_manager.log` dosyasına kaydedilir. |
| ⏱️ **Otomatik Kilit** | 5 dakika hareketsizlik algılandığında oturum kilitlenir. |
| 🔍 **Akıllı Arama** | Binlerce kayıt arasında anlık filtreleme ve arama yapabilir. |
| 📦 **Yedekleme** | Verilerinizi şifreli veya düz metin olarak CSV/JSON formatında dışa aktarın. |

## 🔐 Güvenlik Mimarisi (Technical Specs)

EO Digital Vault, **"Zero-Knowledge"** (Sıfır Bilgi) prensibiyle çalışır. Arka planda çalışan güvenlik mekanizmaları şunlardır:

* **AES Şifreleme (Fernet):** Her bir parola veritabanına kaydedilmeden önce şifrelenir. Veritabanı dosyası çalınsa bile, Master Password olmadan veriler matematiksel olarak çözülemez.
* **Anti-Timing Attack:** Şifre doğrulamalarında `hmac.compare_digest` kullanılarak, saldırganların işlem süresinden şifreyi tahmin etmesi (Side-Channel Attack) engellenmiştir.
* **PBKDF2-HMAC-SHA256:** Master Password, **600.000 iterasyon** (döngü) ile hashlenir. Bu, modern GPU'larla yapılan Brute-Force saldırılarına karşı direnç sağlar.
* **Secure Random:** Şifre üretiminde Python'un standart `random` kütüphanesi yerine, kriptografik olarak güvenli `secrets` modülü kullanılır.

## ✨ Temel Özellikler

* 🎨 **Modern UI:** CustomTkinter ile geliştirilmiş, göz yormayan Dark/Light mod destekli arayüz.
* 🎲 **Şifre Üretici:** Tek tıkla kırılması zor, karmaşık şifreler oluşturun.
* 💾 **Yerel Veritabanı:** İnternet gerektirmez, verileriniz bilgisayarınızda `SQLite` veritabanında kalır.
* 🆔 **Marka Kimliği:** EO Digital Lab güvenlik standartlarına uygun geliştirme.

## 🛠️ Kurulum (Installation)

Projeyi kendi bilgisayarınızda çalıştırmak için:

1.  **Repoyu Klonlayın:**
    ```bash
    git clone [https://github.com/0Ersin0/secure-password-manager.git](https://github.com/0Ersin0/secure-password-manager.git)
    cd secure-password-manager
    ```

2.  **Gerekli Kütüphaneleri Yükleyin:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Uygulamayı Başlatın:**
    ```bash
    python main.py
    ```

## ⚠️ Yasal Sorumluluk Reddi (Disclaimer)

Bu yazılım (EO Digital Vault), eğitim ve portföy geliştirme amaçlı hazırlanmış açık kaynaklı bir projedir.
* **Garanti Yoktur:** Yazılım "OLDUĞU GİBİ" (AS IS) sunulmaktadır.
* **Veri Kaybı:** Master Password'ün unutulması durumunda verilerin kurtarılması **imkansızdır**. Bu bir hata değil, güvenlik özelliğidir.
* **Sorumluluk:** Kullanım sonucu oluşabilecek veri kayıplarından geliştirici sorumlu tutulamaz.

---

**Geliştirici:** Ersin Ö. | **Marka:** EO Digital Lab Security Systems  
*Copyright © 2026 EO Digital Lab. Distributed under the MIT License.*