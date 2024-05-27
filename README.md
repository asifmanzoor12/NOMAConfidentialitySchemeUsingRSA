
# Flask NOMA RSA Encryption Project

This project demonstrates the use of Non-Orthogonal Multiple Access (NOMA) combined with RSA encryption and decryption techniques. The project provides a simple Flask web application where users can generate RSA keys, encrypt messages, simulate NOMA transmission, and decrypt messages.


## Installation

To get started with the project, follow these steps:

1. Clone the repository:
   ```sh
   git clone https://github.com/asifmanzoor12/NOMAConfidentialitySchemeUsingRSA.git
   cd NOMAConfidentialitySchemeUsingRSA
   ```

2. Create a virtual environment:
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
   export FLASK_APP=app.py
   export FLASK_ENV=development
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
