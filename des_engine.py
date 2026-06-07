
def bit_xor(bits1, bits2):
    return "".join(str(int(b1) ^ int(b2)) for b1, b2 in zip(bits1, bits2))

def text_to_bits(text):
    """ String metni bit stringine çevirir (Her karakter 8 bit) """
    return "".join(f"{ord(c):08b}" for c in text)

def bits_to_hex(bit_str):
    """ Bit stringini arayüzde güzel göstermek için Hex formatına çevirir """
    return f"{int(bit_str, 2):016X}"

# --- DES BİR TUR FEISTEL FONKSİYONU ---
def des_round_function(right_32, subkey_48):
    """ 
    DES'in meşhur F fonksiyonu: 
    32-bitlik sağ parça 48 bite genişletilir, anahtarla XOR'lanır, 
    S-Box'lardan geçip tekrar 32 bit olur. (Simüle edilmiş deterministik yapı)
    """
    mixed = ""
    for i in range(32):
        mixed += str(int(right_32[i]) ^ int(subkey_48[i % 48]))
    return mixed

def run_single_des(block_64, key_64, mode="ENCRYPT"):
    L = block_64[:32]
    R = block_64[32:]

    round_logs = []
    round_logs.append(f"Başlangıç: L0={bits_to_hex(L)}, R0={bits_to_hex(R)}")

    subkeys = []
    for round_num in range(1, 17):
        subkey = f"{int(key_64, 2) ^ round_num:048b}"[-48:]
        subkeys.append(subkey)

    if mode == "DECRYPT":
        subkeys = list(reversed(subkeys))
        round_logs.append("DECRYPT modu: Alt anahtarlar ters sırada kullanıldı.")

    for round_num in range(1, 17):
        previous_L = L
        previous_R = R

        f_output = des_round_function(previous_R, subkeys[round_num - 1])

        L = previous_R
        R = bit_xor(previous_L, f_output)

        round_logs.append(
            f"Tur {round_num:02d}: L={bits_to_hex(L)}, R={bits_to_hex(R)}"
        )

    final_bits = R + L
    return final_bits, round_logs

# 3-DES
def run_3des_simulation(plaintext, key1, key2, key3):
    """ 3-DES Şifrele-Çöz-Şifrele (EDE) Mekanizması """
    # Girdileri 64-bitlik bit bloklarına çeviriyoruz
    block_64 = text_to_bits(plaintext.ljust(8, '\0')[:8])
    k1_64 = text_to_bits(key1.ljust(8, '\0')[:8])
    k2_64 = text_to_bits(key2.ljust(8, '\0')[:8])
    k3_64 = text_to_bits(key3.ljust(8, '\0')[:8])
    
    all_steps = []
    
    # Adım 1: K1 ile DES Şifreleme (Encrypt)
    all_steps.append("=== ADIM 1: K1 Anahtarı ile DES Şifreleme ===")
    step1_bits, logs1 = run_single_des(block_64, k1_64, "ENCRYPT")
    all_steps.extend(logs1)
    all_steps.append(f"Adım 1 Çıktısı (Hex): {bits_to_hex(step1_bits)}\n")
    
    # Adım 2: K2 ile DES Deşifreleme (Decrypt)
    all_steps.append("=== ADIM 2: K2 Anahtarı ile DES Deşifreleme (EDE Modu) ===")
    step2_bits, logs2 = run_single_des(step1_bits, k2_64, "DECRYPT")
    all_steps.extend(logs2)
    all_steps.append(f"Adım 2 Çıktısı (Hex): {bits_to_hex(step2_bits)}\n")
    
    # Adım 3: K3 ile DES Şifreleme (Encrypt)
    all_steps.append("=== ADIM 3: K3 Anahtarı ile Son Şifreleme ===")
    final_bits, logs3 = run_single_des(step2_bits, k3_64, "ENCRYPT")
    all_steps.extend(logs3)
    
    final_hex = bits_to_hex(final_bits)
    all_steps.append(f"Nihai 3-DES Çıktısı (Hex): {final_hex}")
    
    return final_hex, all_steps