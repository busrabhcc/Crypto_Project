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

# --- YENİ: DES / 3-DES ENDPOINT'İ ---
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
    k1 = data.get('k1', '')  # Sadece tek anahtar alıyor
    
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
        v1 = int(data.get('v1', '00'), 16)
        v2 = int(data.get('v2', '00'), 16)
        v3 = int(data.get('v3', '00'), 16)
        v4 = int(data.get('v4', '00'), 16)
    except ValueError:
        return jsonify({'error': 'Lütfen geçerli HEX değerleri girin!'}), 400

    part1 = gf_mul2(v1)
    part2 = gf_mul3(v2)
    part3 = v3
    part4 = v4

    result = part1 ^ part2 ^ part3 ^ part4
    
    mix_steps = [
        f"02 × {data.get('v1').upper()} = {part1:02X}",
        f"03 × {data.get('v2').upper()} = {part2:02X}",
        f"01 × {data.get('v3').upper()} = {part3:02X}",
        f"01 × {data.get('v4').upper()} = {part4:02X}",
        f"Nihai XOR Sonucu (MixColumns Çıktısı) = {result:02X}"
    ]

    return jsonify({
        'mixResult': f"{result:02X}",
        'mixSteps': mix_steps
    })
# app.py içerisine eklenecek yeni route'lar:

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