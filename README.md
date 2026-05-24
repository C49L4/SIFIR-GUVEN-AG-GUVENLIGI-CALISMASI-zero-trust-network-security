
```markdown
# Sıfır Güven (Zero Trust) Ağ Güvenliği Çalışması

Bu proje, modern siber güvenlikte "Asla güvenme, her zaman doğrula" (Never Trust, Always Verify) prensibini temel alan bir API güvenlik mimarisidir. 

##  Proje Hakkında
Bu çalışma, FastAPI framework'ü ile geliştirilmiştir. Sisteme gelen her istek, kaynağı ne olursa olsun güvenlik katmanlarından geçmek zorundadır. Proje, yetkisiz erişimi engellemek, şüpheli aktiviteleri izlemek ve kimlik doğrulamasını sıkı kurallara bağlamak için tasarlanmıştır.

### Temel Özellikler
* **JWT (JSON Web Token) Kimlik Doğrulama:** 15 dakika geçerlilik süresine sahip, güvenli token tabanlı erişim kontrolü.
* **Sıfır Güven Middleware:** Her gelen HTTP isteği, sistem tarafından anlık olarak izlenir ve doğrulanır.
* **Honeypot (Tuzak) Mekanizması:** Saldırganların sık kullandığı `admin-config.php`, `.env` gibi dosyalar için sahte yollar tanımlanmıştır. İzinsiz erişim denemeleri anında engellenir ve loglanır.
* **Gelişmiş Loglama:** Tüm trafik akışı, IP adresleri ve zaman bilgileriyle birlikte kayıt altına alınır.
* **Güvenli Şifreleme:** Kullanıcı şifreleri `bcrypt` kütüphanesi ile yüksek güvenlikli şekilde hashlenerek saklanır.

##  Kurulum ve Başlatma

1. **Depoyu klonlayın:**
   ```bash
   git clone [https://github.com/C49L4/SIFIR-GUVEN-AG-GUVENLIGI-CALISMASI-zero-trust-network-security.git](https://github.com/C49L4/SIFIR-GUVEN-AG-GUVENLIGI-CALISMASI-zero-trust-network-security.git)

```

2. **Sanal ortam oluşturun ve aktif edin:**
```bash
python -m venv venv
source venv/bin/activate

```


3. **Gerekli kütüphaneleri yükleyin:**
```bash
pip install fastapi uvicorn python-jose[cryptography] bcrypt python-dotenv

```


4. **Projeyi başlatın:**
```bash
uvicorn main:app --reload

```



## Güvenlik ve Yetkilendirme

Proje, istemci ve sunucu arasındaki tüm iletişimi şifreler ve yetkilendirir. `/admin-area` ve `/user-area` gibi korumalı rotalara erişmek için öncelikle `/login` endpoint'i üzerinden giriş yaparak bir `Bearer Token` alınması gerekmektedir.

* **Dokümantasyon:** Proje çalışırken `http://127.0.0.1:8000/docs` adresinden tüm endpoint'leri interaktif olarak inceleyebilirsiniz.
* **İzleme:** `http://127.0.0.1:8000/logs` adresi üzerinden sistemin tüm trafik geçmişini görüntüleyebilirsiniz.

---

*Bu çalışma, Zero Trust ağ güvenliği mimarilerinin temel prensiplerini uygulamalı olarak göstermek amacıyla hazırlanmıştır.*

```

Bunu doğrudan `README.md` dosyana yapıştırıp kaydedebilirsin. Başka bir ihtiyaç olursa buradayım!

```
