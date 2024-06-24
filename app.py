from flask import Flask, render_template, request, session
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import math
from collections import Counter

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Set a secret key for session management

# RSA Key Generation
def generate_rsa_keypair(key_size=1024):
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    print(f'Generated key pair - Public Key: {public_key[:30]}..., Private Key: {private_key[:30]}...')
    return public_key, private_key

# Message Encryption
def encrypt_message(public_key, message):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    encrypted_message = cipher.encrypt(message.encode())
    encrypted_message_base64 = base64.b64encode(encrypted_message).decode()
    print(f'Encrypted message: {encrypted_message_base64}')
    return encrypted_message_base64

# Message Decryption
def decrypt_message(private_key, encrypted_message):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    decrypted_message = cipher.decrypt(base64.b64decode(encrypted_message)).decode()
    print(f'Decrypted message: {decrypted_message}')
    return decrypted_message

# Simulate NOMA Transmission
def simulate_noma_transmission(messages, powers):
    combined_signal = [(m, p) for m, p in zip(messages, powers)]
    print(f'NOMA transmission: {combined_signal}')
    return combined_signal

# Masking Function
def mask_key(key, visible_chars=10):
    return key[:visible_chars] + '...' + key[-visible_chars:]

# Shannon Entropy Calculation
def shannon_entropy(data):
    entropy = 0.0
    length = len(data)
    if length == 0:
        return entropy

    count_data = Counter(data)
    
    for count in count_data.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    print(f'Shannon entropy of data "{data}": {entropy}')
    return entropy

@app.route('/')
def index():
    print('Rendering index page')
    return render_template('index.html')

@app.route('/keys', methods=['GET', 'POST'])
def keys():
    if request.method == 'POST':
        public_key_user1, private_key_user1 = generate_rsa_keypair()
        public_key_user2, private_key_user2 = generate_rsa_keypair()
        public_key_bs, private_key_bs = generate_rsa_keypair()
        keys = {
            'public_key_user1': public_key_user1.decode(),
            'private_key_user1': private_key_user1.decode(),
            'public_key_user2': public_key_user2.decode(),
            'private_key_user2': private_key_user2.decode(),
            'public_key_bs': public_key_bs.decode(),
            'private_key_bs': private_key_bs.decode()
        }
        masked_keys = {k: mask_key(v) for k, v in keys.items()}
        print(f'Generated and masked keys: {masked_keys}')
        session['keys'] = keys  # Store keys in session
        
        return render_template('keys.html', keys=keys, masked_keys=masked_keys)
        
    print('Rendering keys page')
    return render_template('keys.html')

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'POST':
        public_key_bs = request.form['public_key_bs']
        message_user1 = request.form['message_user1']
        message_user2 = request.form['message_user2']
        print(f'Received messages for encryption: User1: {message_user1}, User2: {message_user2}')
        
        entropy_user1 = shannon_entropy(message_user1)
        entropy_user2 = shannon_entropy(message_user2)
        
        encrypted_message_user1 = encrypt_message(public_key_bs, message_user1)
        encrypted_message_user2 = encrypt_message(public_key_bs, message_user2)

        encrypted_messages = {
            'encrypted_message_user1': encrypted_message_user1,
            'encrypted_message_user2': encrypted_message_user2
        }
        print(f'Encrypted messages: {encrypted_messages}')

        session['encrypted_messages'] = encrypted_messages  # Store encrypted messages in session
        return render_template('encrypt.html', encrypted_messages=encrypted_messages, entropy_user1=entropy_user1, entropy_user2=entropy_user2)

    keys = session.get('keys', {})
    masked_keys = {k: mask_key(v) for k, v in keys.items()}
    print(f'Keys for encryption page: {masked_keys}')
    return render_template('encrypt.html', keys=keys, masked_keys=masked_keys)

@app.route('/noma', methods=['GET', 'POST'])
def noma():
    if request.method == 'POST':
        encrypted_messages = session.get('encrypted_messages', {})
        encrypted_message_user1 = encrypted_messages.get('encrypted_message_user1')
        encrypted_message_user2 = encrypted_messages.get('encrypted_message_user2')
        print(f'Encrypted messages for NOMA: User1: {encrypted_message_user1}, User2: {encrypted_message_user2}')
        
        power_user1 = float(request.form['power_user1'])
        power_user2 = float(request.form['power_user2'])
        print(f'Received power levels: User1: {power_user1}, User2: {power_user2}')

        noma_transmissions = simulate_noma_transmission(
            [encrypted_message_user1, encrypted_message_user2],
            [power_user1, power_user2]
        )

        transmissions = [{'message': m, 'power': p} for m, p in noma_transmissions]
        print(f'NOMA transmissions: {transmissions}')
        session['transmissions'] = transmissions  # Store transmissions in session

        return render_template('noma.html', transmissions=transmissions)

    encrypted_messages = session.get('encrypted_messages', {})
    print('Rendering NOMA page')
    return render_template('noma.html', encrypted_messages=encrypted_messages)

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    decrypted_messages = []

    if request.method == 'POST':
        private_key_bs = session['keys']['private_key_bs']
        transmissions = session.get('transmissions', [])
        print(f'Transmissions for decryption: {transmissions}')

        for transmission in transmissions:
            decrypted_message = decrypt_message(private_key_bs, transmission['message'])
            decrypted_messages.append({'message': decrypted_message, 'power': transmission['power']})

        print(f'Decrypted messages: {decrypted_messages}')
        session['decrypted_messages'] = decrypted_messages  # Store decrypted messages in session
        
        return render_template('decrypt.html', decrypted_messages=decrypted_messages)
    
    encrypted_messages = session.get('encrypted_messages', {})
    print('Rendering decrypt page')
    return render_template('decrypt.html', encrypted_messages=encrypted_messages)

if __name__ == '__main__':
    print('Starting Flask application')
    app.run(debug=True, port=2000)
