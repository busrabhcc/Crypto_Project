from flask import Flask, render_template, request, jsonify
from crypto_engine import run_aes_simulation, gf_mul2, gf_mul3
from des_engine import run_3des_simulation  
from hash_engine import run_sha256_simulation, run_hmac_simulation, run_rbg_simulation

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    message = data.get('message', '')
    key = data.get('key', '')
    
    if not message or not key:
        return jsonify({'error': 'Mesaj ve anahtar boş olamaz!'}), 400
        
    cipher_text, steps = run_aes_simulation(message, key)
    return jsonify({
        'cipherText': cipher_text,
        'steps': steps
    })

@app.route('/api/encrypt_des', methods=['POST'])
def encrypt_des():
    data = request.json
    message = data.get('message', '')
    k1 = data.get('k1', '')
    k2 = data.get('k2', '')
    k3 = data.get('k3', '')
    
    if not message or not k1 or not k2 or not k3:
        return jsonify({'error': 'Lütfen mesajı ve 3 anahtarı da doldurun!'}), 400
        
    cipher_text, steps = run_3des_simulation(message, k1, k2, k3)
    return jsonify({
        'cipherText': cipher_text,
        'steps': steps
    })

@app.route('/api/encrypt_just_des', methods=['POST'])
def encrypt_just_des():
    data = request.json
    message = data.get('message', '')
    k1 = data.get('k1', '')  
    
    if not message or not k1:
        return jsonify({'error': 'Lütfen mesajı ve anahtarı doldurun!'}), 400
        
    from des_engine import text_to_bits, run_single_des, bits_to_hex
    
    # 64-bitlik bloklara ve anahtara çevir
    block_64 = text_to_bits(message.ljust(8, '\0')[:8])
    k1_64 = text_to_bits(k1.ljust(8, '\0')[:8])
    
    # Sadece 1 kez DES çalıştır (16 Tur)
    cipher_bits, steps = run_single_des(block_64, k1_64, "ENCRYPT")
    
    return jsonify({
        'cipherText': bits_to_hex(cipher_bits),
        'steps': steps
    })

@app.route('/api/galois_sandbox', methods=['POST'])
def galois_sandbox():
    data = request.json
    try:
        hex1 = data.get('v1', '00').upper()
        hex2 = data.get('v2', '00').upper()
        hex3 = data.get('v3', '00').upper()
        hex4 = data.get('v4', '00').upper()

        v1 = int(hex1, 16)
        v2 = int(hex2, 16)
        v3 = int(hex3, 16)
        v4 = int(hex4, 16)
    except ValueError:
        return jsonify({'error': 'Lütfen geçerli HEX değerleri girin!'}), 400

    # 02 ile Çarpım Detayları 
    part1 = gf_mul2(v1)
    msb1 = (v1 & 0x80) >> 7  
    shifted1 = (v1 << 1) & 0xFF
    step1_details = {
        "title": f"02 × {hex1} = {part1:02X}",
        "logic": "02 ile çarpmak (xtime), sayıyı 1 bit sola kaydırmak demektir. Eğer MSB 1 ise sonuç 0x1B ile XOR'lanır.",
        "binary_flow": (
            f"{hex1} = {v1:08b}\n"
            f"1 Bit Sola Kaydırma ➔ {shifted1:08b}\n"
            f"{'MSB = 1 olduğu için 0x1B ile XOR yapıldı.' if msb1 else 'MSB = 0 olduğu için 0x1B ile XOR yapılmadı.'}\n"
            f"Sonuç: {part1:02X} ({part1:08b})"
        )
    }

    # 03 ile Çarpım Detayları
    part2 = gf_mul3(v2)
    mul2_of_v2 = gf_mul2(v2)  # 03 * x = (02 * x) ^ (01 * x)
    step2_details = {
        "title": f"03 × {hex2} = {part2:02X}",
        "logic": "03 ile çarpmak, işlemi (02 ⊕ 01) × V = (02 × V) ⊕ V şeklinde parçalamak demektir.",
        "binary_flow": (
            f"1) (02 × {hex2}) hesaplanır ➔ {mul2_of_v2:02X} ({mul2_of_v2:08b})\n"
            f"2) Sonuç kendisi ({hex2}) ile XOR'lanır:\n"
            f"   {mul2_of_v2:02X} ➔ {mul2_of_v2:08b}\n"
            f"   {hex2} ➔ {v2:08b}\n"
            f"   ------------------- (XOR)\n"
            f"Sonuç: {part2:02X} ({part2:08b})"
        )
    }

    #  01 ile Çarpım Detayları 
    part3 = v3
    part4 = v4
    step3_details = {
        "title": f"01 × {hex3} = {part3:02X}",
        "logic": "Galois Alanında 01 ile çarpmak etkisiz elemandır. Sayı aynen korunur.",
        "binary_flow": f"{hex3} ➔ {part3:02X} ({part3:08b})"
    }
    step4_details = {
        "title": f"01 × {hex4} = {part4:02X}",
        "logic": "Galois Alanında 01 ile çarpmak etkisiz elemandır. Sayı aynen korunur.",
        "binary_flow": f"{hex4} ➔ {part4:02X} ({part4:08b})"
    }

    # Nihai XOR Sonucu
    result = part1 ^ part2 ^ part3 ^ part4
    step5_details = {
        "title": f"Nihai XOR Sonucu (MixColumns Çıktısı) = {result:02X}",
        "logic": "Elde edilen tüm ara değerler bit düzeyinde birbiriyle XOR işlemine tabi tutulur.",
        "binary_flow": (
            f"Adım 1 ({part1:02X}) ➔ {part1:08b}\n"
            f"Adım 2 ({part2:02X}) ➔ {part2:08b}\n"
            f"Adım 3 ({part3:02X}) ➔ {part3:08b}\n"
            f"Adım 4 ({part4:02X}) ➔ {part4:08b}\n"
            f"-------------------------\n"
            f"Çıktı  ({result:02X}) ➔ {result:08b}"
        )
    }

    
    mix_steps = [step1_details, step2_details, step3_details, step4_details, step5_details]

    return jsonify({
        'mixResult': f"{result:02X}",
        'mixSteps': mix_steps
    })

@app.route('/api/hash_analysis', methods=['POST'])
def hash_analysis():
    data = request.json
    message = data.get('message', '')
    if not message:
        return jsonify({'error': 'Mesaj alanı boş olamaz!'}), 400
    hash_res, steps = run_sha256_simulation(message)
    return jsonify({'result': hash_res, 'steps': steps})

@app.route('/api/hmac_analysis', methods=['POST'])
def hmac_analysis():
    data = request.json
    message = data.get('message', '')
    key = data.get('key', '')
    if not message or not key:
        return jsonify({'error': 'Mesaj ve anahtar boş olamaz!'}), 400
    hmac_res, steps = run_hmac_simulation(message, key)
    return jsonify({'result': hmac_res, 'steps': steps})

@app.route('/api/rbg_simulation', methods=['POST'])
def rbg_simulation():
    data = request.json
    try:
        bit_length = int(data.get('bitLength', 128))
    except ValueError:
        bit_length = 128
    hex_res, bit_res, steps = run_rbg_simulation(bit_length)
    return jsonify({'hexResult': hex_res, 'bitResult': bit_res, 'steps': steps})

if __name__ == '__main__':
    app.run(debug=True, port=5000)