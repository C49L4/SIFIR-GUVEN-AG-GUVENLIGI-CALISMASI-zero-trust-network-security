Sıfır Güven yaklaşımına dayalı güvenli servis erişim sistemi. Kullanıcı kimlik doğrulama, rol tabanlı yetkilendirme ve istek bazlı güvenlik kontrolü içermektedir.

# Sıfır Güven (Zero Trust) Ağ Güvenliği Çalışması

Bu proje, modern ağ güvenliğinin temel prensibi olan "Asla güvenme, her zaman doğrula" (Never Trust, Always Verify) yaklaşımını temel alan bir API sistemidir.

## 🛠️ Proje Hakkında
Bu çalışma, FastAPI framework'ü kullanılarak geliştirilmiştir. Temel amacı, yetkisiz erişimleri engellemek, her isteği doğrulamak ve sistem üzerindeki şüpheli hareketleri izlemektir.

### Öne Çıkan Özellikler:
* **JWT Tabanlı Kimlik Doğrulama:** Token süreli (15 dk) güvenli erişim.
* **Zero Trust Middleware:** Her istek (request) doğrulamadan geçer.
* **Honeypot (Tuzak) Mekanizması:** Saldırganların sık kullandığı yolları izleyerek erişim girişimlerini engeller.
* **Merkezi Loglama:** Tüm trafik akışını kayıt altına alır.
* **Güvenli Şifreleme:** `bcrypt` ile şifre hashing.

## 🚀 Kurulum

1. Depoyu klonlayın:
   ```bash
   git clone [https://github.com/C49L4/SIFIR-GUVEN-AG-GUVENLIGI-CALISMASI-zero-trust-network-security.git](https://github.com/C49L4/SIFIR-GUVEN-AG-GUVENLIGI-CALISMASI-zero-trust-network-security.git)

2. Sanal ortamı oluşturun ve aktif edin:
  ```bash
python -m venv venv
source venv/bin/activate

3. Gerekli kütüphaneleri yükleyin:
Bash

pip install -r requirements.txt

Projeyi başlatın:
Bash

    uvicorn main:app --reload

🛡️ Güvenlik Katmanı

Proje, istemci ve sunucu arasındaki güven ilişkisini JWT token'ları ile yöneterek, sadece yetkili kullanıcıların korunan rotalara erişmesine izin verir.



