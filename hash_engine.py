import hashlib
import hmac as hmac_lib
import secrets

def run_sha256_simulation(text):
    """ SHA-256 Hash üretir ve Avalanche Effect (Çığ Etkisi) analizi yapar """
    if not text:
        return "", []
        
    # Gerçek SHA-256 Hash Hesabı
    sha256_hash = hashlib.sha256(text.encode('utf-8')).hexdigest().upper()

    alt_text = text[:-1] + ("X" if text[-1] != "X" else "Y") if text else "X"
    alt_hash = hashlib.sha256(alt_text.encode('utf-8')).hexdigest().upper()
    
    analysis_steps = [
        f"Girdi Verisi: '{text}'",
        f"Veri Bütünlüğü (Integrity) Kontrolü: SHA-256 algoritması girdi boyutundan bağımsız olarak her zaman sabit 256-bit (64 Hex karakter) çıktı üretir.",
        f"--- Avalanche Effect (Çığ Etkisi) Analizi ---",
        f"Orijinal Girdi: '{text}' -> Hash: {sha256_hash}",
        f"Değiştirilmiş Girdi: '{alt_text}' (Sadece son karakter değişti) -> Hash: {alt_hash}",
        "Analiz Sonucu: Girdideki tek bir bitin/harfin değişmesi, özet değerinin (hash) yarıdan fazlasının tamamen değişmesine neden olur. Bu durum veri bütünlüğünün kesin kanıtıdır."
    ]
    
    return sha256_hash, analysis_steps

def run_hmac_simulation(text, key):
    """ SHA-256 altyapılı HMAC üreterak Kimlik Doğrulama analizi yapar """
    if not text or not key:
        return "", []
        
    # Gerçek HMAC-SHA256 Hesabı
    hmac_code = hmac_lib.new(key.encode('utf-8'), text.encode('utf-8'), hashlib.sha256).hexdigest().upper()
    
    analysis_steps = [
        f"Mesaj: '{text}' | Gizli Anahtar: '{key}'",
        "HMAC Çalışma Prensibi: HMAC = Hash(Key XOR opad || Hash(Key XOR ipad || Mesaj))",
        "Kimlik Doğrulama (Authentication) Rolü: Alıcı taraf da aynı gizli anahtara sahipse, gelen mesajın HMAC değerini hesaplar. Eğer eşleşiyorsa mesajın hem değişmediği (bütünlük) hem de doğru kişiden geldiği (kimlik) doğrulanır."
    ]
    
    return hmac_code, analysis_steps

def run_rbg_simulation(bit_length=128):
    bit_length = max(8, min(bit_length, 4096))

    byte_length = (bit_length + 7) // 8
    random_bytes = secrets.token_bytes(byte_length)

    bit_string = "".join(f"{b:08b}" for b in random_bytes)[:bit_length]
    hex_string = random_bytes.hex().upper()

    ones = bit_string.count("1")
    zeros = bit_string.count("0")
    ones_ratio = ones / bit_length
    zeros_ratio = zeros / bit_length

    analysis_steps = [
        f"İstenen Bit Uzunluğu: {bit_length}-bit",
        "Kullanılan Üreteç: Python secrets modülü.",
        "Bu modül işletim sistemi tabanlı kriptografik rastgelelik kaynağını kullanır.",
        f"Üretilen 0 sayısı: {zeros}",
        f"Üretilen 1 sayısı: {ones}",
        f"0 Oranı: {zeros_ratio:.2f}",
        f"1 Oranı: {ones_ratio:.2f}",
        "Basit Monobit Testi: Kriptografik rastgelelikte 0 ve 1 dağılımının yaklaşık dengeli olması beklenir.",
        "Not: Bu test tek başına güvenlik kanıtı değildir; yalnızca eğitimsel bir istatistiksel kontroldür."
    ]

    return hex_string, bit_string, analysis_steps