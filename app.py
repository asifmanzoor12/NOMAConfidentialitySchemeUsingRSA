from flask import Flask, render_template, request, redirect, url_for, flash
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

app = Flask(__name__)
app.secret_key = 'sdbfjsdbfjsdbfjhasdbfjhasdbfa'

# RSA Key Generation
def generate_rsa_keypair(key_size=2048):
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key

# Message Encryption
def encrypt_message(public_key, message):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    encrypted_message = cipher.encrypt(message)
    return base64.b64encode(encrypted_message)

# Message Decryption
def decrypt_message(private_key, encrypted_message):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    decrypted_message = cipher.decrypt(base64.b64decode(encrypted_message))
    return decrypted_message

# Simulate NOMA Transmission
def simulate_noma_transmission(messages, powers):
    combined_signal = [(m, p) for m, p in zip(messages, powers)]
    return combined_signal

@app.route('/')
def index():
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
        return render_template('keys.html', keys=keys)
    return render_template('keys.html')

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'POST':
        public_key_bs = request.form['public_key_bs'].encode()
        message_user1 = request.form['message_user1'].encode()
        message_user2 = request.form['message_user2'].encode()
        
        encrypted_message_user1 = encrypt_message(public_key_bs, message_user1)
        encrypted_message_user2 = encrypt_message(public_key_bs, message_user2)

        encrypted_messages = {
            'encrypted_message_user1': encrypted_message_user1.decode(),
            'encrypted_message_user2': encrypted_message_user2.decode()
        }
        return render_template('encrypt.html', encrypted_messages=encrypted_messages)
    return render_template('encrypt.html')

@app.route('/noma', methods=['GET', 'POST'])
def noma():
    if request.method == 'POST':
        encrypted_message_user1 = request.form['encrypted_message_user1'].encode()
        encrypted_message_user2 = request.form['encrypted_message_user2'].encode()
        power_user1 = float(request.form['power_user1'])
        power_user2 = float(request.form['power_user2'])

        noma_transmissions = simulate_noma_transmission(
            [encrypted_message_user1, encrypted_message_user2],
            [power_user1, power_user2]
        )

        transmissions = [
            {'message': m.decode(), 'power': p} for m, p in noma_transmissions
        ]
        return render_template('noma.html', transmissions=transmissions)
    return render_template('noma.html')

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        private_key_bs = request.form['private_key_bs'].encode()
        encrypted_message_user1 = request.form['encrypted_message_user1'].encode()
        encrypted_message_user2 = request.form['encrypted_message_user2'].encode()
        power_user1 = float(request.form['power_user1'])
        power_user2 = float(request.form['power_user2'])

        noma_transmissions = simulate_noma_transmission(
            [encrypted_message_user1, encrypted_message_user2],
            [power_user1, power_user2]
        )

        decrypted_messages = []
        for encrypted_message, power in noma_transmissions:
            decrypted_message = decrypt_message(private_key_bs, encrypted_message)
            decrypted_messages.append({'message': decrypted_message.decode(), 'power': power})

        return render_template('decrypt.html', decrypted_messages=decrypted_messages)
    return render_template('decrypt.html')

if __name__ == '__main__':
    app.run(debug=True)

