
# Flask NOMA RSA Encryption Project

This project demonstrates the use of Non-Orthogonal Multiple Access (NOMA) combined with RSA encryption and decryption techniques. The project provides a simple Flask web application where users can generate RSA keys, encrypt messages, simulate NOMA transmission, and decrypt messages.


## Installation

To get started with the project, follow these steps:

1. Clone the repository:
   ```sh
   git clone https://github.com/asifmanzoor12/NOMAConfidentialitySchemeUsingRSA.git
   cd NOMAConfidentialitySchemeUsingRSA
   ```

2. Create a virtual environment(Optional):
   ```sh
   python -m venv venv
   source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
   ```

3. Install the required packages:
   ```sh
   pip install -r requirements.txt
   ```

4. Set the Flask environment variables:
   ```sh
   set FLASK_APP=app.py
   set FLASK_ENV=development
   ```

5. Run the Flask application:
   ```sh
   flask run
   ```

## Usage

### Key Generation

1. Navigate to the `/keys` endpoint to generate RSA key pairs for two users and the base station.
2. The keys will be displayed on the page.

### Message Encryption

1. Navigate to the `/encrypt` endpoint.
2. Enter the messages for User 1 and User 2 along with the base station's public key.
3. The encrypted messages will be displayed on the page.

### NOMA Transmission

1. Navigate to the `/noma` endpoint.
2. Enter the encrypted messages and power levels for User 1 and User 2.
3. The combined NOMA transmission will be displayed on the page.

### Message Decryption

1. Navigate to the `/decrypt` endpoint.
2. Enter the base station's private key, encrypted messages, and power levels.
3. The decrypted messages will be displayed on the page.

## API Endpoints

- `/` - Home page.
- `/keys` - Generate RSA key pairs.
- `/encrypt` - Encrypt messages.
- `/noma` - Simulate NOMA transmission.
- `/decrypt` - Decrypt messages.

## Docker Setup

To run the project using Docker, follow these steps:

1. Build the Docker image:
   ```sh
   docker build -t noma:latest .
   ```

2. Run the Docker container:
   ```sh
   docker run -dit -name noma-app -p 5000:5000 noma:latest
   ```

3. Access the application at `http://localhost:5000`.


Sure! Let's break down the Flask application code into different parts and explain each one in detail.

### Imports and App Setup

```python
from flask import Flask, render_template, request
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

app = Flask(__name__)
app.secret_key = 'your_secret_key'
```

- `Flask` is imported from the `flask` module to create the web application.
- `render_template` is imported to render HTML templates.
- `request` is imported to handle HTTP requests.
- `RSA` and `PKCS1_OAEP` are classes from the `Crypto.PublicKey` and `Crypto.Cipher` modules of the `pycryptodome` library for RSA encryption.
- `base64` is imported to encode and decode messages.

### Key Generation

```python
def generate_rsa_keypair(key_size=2048):
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key
```

- `generate_rsa_keypair` function generates a new RSA key pair of the specified `key_size` (default is 2048 bits).
- The function returns the public and private keys as strings.

### Message Encryption

```python
def encrypt_message(public_key, message):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    encrypted_message = cipher.encrypt(message)
    return base64.b64encode(encrypted_message)
```

- `encrypt_message` function encrypts a message using the provided public key.
- It imports the public key, creates an encryption cipher, encrypts the message, and returns the encrypted message as a base64-encoded string.

### Message Decryption

```python
def decrypt_message(private_key, encrypted_message):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    decrypted_message = cipher.decrypt(base64.b64decode(encrypted_message))
    return decrypted_message
```

- `decrypt_message` function decrypts an encrypted message using the provided private key.
- It imports the private key, creates a decryption cipher, decrypts the message, and returns the decrypted message.

### Simulation of NOMA Transmission

```python
def simulate_noma_transmission(messages, powers):
    combined_signal = [(m, p) for m, p in zip(messages, powers)]
    return combined_signal
```

- `simulate_noma_transmission` function simulates a NOMA transmission by combining encrypted messages with power levels.
- It takes a list of encrypted messages and a list of power levels, zips them together, and returns the combined signal.

### Routes and Views

The Flask application defines routes for different parts of the process: generating keys, encrypting messages, simulating NOMA transmission, and decrypting messages. Each route corresponds to a different HTML template.

### HTML Templates

The HTML templates (`index.html`, `keys.html`, `encrypt.html`, `noma.html`, `decrypt.html`) provide the user interface for the application. They use Bootstrap for styling and contain forms for user input and display areas for messages and keys.

### Running the Application

- The `if __name__ == '__main__':` block at the end of the script runs the Flask application when the script is executed directly.
- The `app.run(debug=True)` method starts the Flask development server with debugging enabled.

### Summary

The Flask application provides a user-friendly interface for demonstrating the NOMA confidentiality scheme using RSA encryption. It guides the user through the key generation, encryption, NOMA simulation, and decryption steps, with clear explanations and interactive forms for input.
