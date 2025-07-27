# client_customer.py
import asyncio
import websockets
import json
import base64
import os
import sys
import time
import random
import logging
import ssl
from datetime import datetime # Import datetime for timestamp formatting

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature, InvalidTag

# --- IMPORTANT: Set logging level to DEBUG to see all crucial prints ---
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Suppress websockets library's PING/PONG debug logs ---
logging.getLogger('websockets').setLevel(logging.INFO) # Set to INFO or WARNING

# --- Configuration Constants ---
SERVER_URI = "wss://localhost:8765"
ROLE = "customer" # Change to "bank" for client_bank.py
IDENTITY_KEY_FILE = f"{ROLE}_identity_keys.json"
# Peer public key will now be stored in a JSON file for easier manual exchange
PEER_PUBLIC_KEY_FILE = f"{'bank' if ROLE == 'customer' else 'customer'}_public_identity_key.json"

# Interval for sending dummy messages (in seconds)
DUMMY_MESSAGE_INTERVAL_MIN = 30
DUMMY_MESSAGE_INTERVAL_MAX = 90

# --- Global State ---
identity_key_pair = None # ECDSA for signing
peer_public_identity_key = None # Peer's ECDSA public key for verification
ephemeral_key_pair = None # ECDH for session key exchange
shared_session_key = None # Derived AES-256-GCM key (bytes)
my_session_id = None # Assigned by server
peer_session_id = None # Session ID of the peer client (needs to be set manually for PoC)
seen_nonces = set() # For replay protection

# --- Helper Functions for Cryptography ---

def bytes_to_base64(b: bytes) -> str:
    """Converts bytes to a Base64 string."""
    return base64.b64encode(b).decode('utf-8')

def base64_to_bytes(s: str) -> bytes:
    """Converts a Base64 string to bytes."""
    return base64.b64decode(s.encode('utf-8'))

# Helper to get public key's raw bytes for comparison
def public_key_to_hex_bytes(public_key_obj) -> str:
    """Exports a public key's raw uncompressed point bytes to hex for comparison."""
    return public_key_obj.public_bytes(
        encoding=serialization.Encoding.X962, # Standard encoding for EC public keys
        format=serialization.PublicFormat.UncompressedPoint # Ensures consistent format
    ).hex()

async def generate_identity_key_pair():
    """Generates an ECDSA P-256 key pair."""
    logging.info(f"Generating {ROLE} identity key pair...")
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

async def generate_ephemeral_key_pair():
    """Generates an ECDH P-256 key pair."""
    logging.info(f"Generating {ROLE} ephemeral key pair...")
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

async def derive_shared_secret(private_key_ephemeral, public_key_peer_ephemeral):
    """Derives a shared secret using ECDH."""
    logging.info("Deriving shared secret...")
    shared_key_material = private_key_ephemeral.exchange(ec.ECDH(), public_key_peer_ephemeral)
    
    # Use HKDF to derive a strong, fixed-length key for AES-256-GCM
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32, # 256 bits for AES-256
        salt=None, # No salt for simplicity, but recommended for real apps
        info=b'handshake data', # Contextual info
        backend=default_backend()
    )
    return hkdf.derive(shared_key_material)

def encrypt_message(key: bytes, plaintext_bytes: bytes, nonce: bytes):
    """Encrypts plaintext using AES-256-GCM."""
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
    tag = encryptor.tag
    return ciphertext, tag

def decrypt_message(key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes):
    """Decrypts ciphertext using AES-256-GCM and verifies tag."""
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize() # This will raise InvalidTag if tag is bad
    return plaintext

def sign_data(private_key_ecdsa, data_to_sign: bytes):
    """Signs data using ECDSA P-256."""
    # Correct way to sign directly on the private key object
    signature = private_key_ecdsa.sign(
        data_to_sign,
        ec.ECDSA(hashes.SHA256())
    )
    return signature

def verify_signature(public_key_ecdsa, data_to_verify: bytes, signature: bytes):
    """Verifies signature using ECDSA P-256."""
    try:
        # Correct way to verify directly on the public key object
        public_key_ecdsa.verify(
            signature,
            data_to_verify,
            ec.ECDSA(hashes.SHA256())
        )
        return True # If no exception, it's valid
    except InvalidSignature:
        # Catch the specific InvalidSignature exception and re-raise it
        raise
    except Exception as e:
        # Catch any other unexpected errors during verification
        logging.error(f"Unexpected error during signature verification: {e}")
        raise # Re-raise the exception

# --- Key Management (Load/Save JSON for public keys) ---

def export_public_key_to_pem_str(public_key) -> str:
    """Exports a public key to PEM string format."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

def import_public_key_from_pem_str(pem_str: str):
    """Imports a public key from PEM string format."""
    return serialization.load_pem_public_key(
        pem_str.encode('utf-8'),
        backend=default_backend()
    )

def export_private_key_to_pem_str(private_key) -> str:
    """Exports a private key to PEM string format."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption() # For PoC, no encryption
    ).decode('utf-8')

def import_private_key_from_pem_str(pem_str: str):
    """Imports a private key from PEM string format."""
    return serialization.load_pem_private_key(
        pem_str.encode('utf-8'),
        password=None, # For PoC, no password
        backend=default_backend()
    )

# NEW FUNCTION: Programmatically write peer's public key to file
def write_peer_public_key_to_file(peer_role: str, public_key_pem_str: str):
    """Writes the peer's public identity key to a JSON file."""
    # This function is called by the client (e.g., customer) to save the bank's public key,
    # or by the bank to save the customer's public key.
    # So, peer_role_to_save will be 'bank' if current ROLE is 'customer', and vice versa.
    filename = f"{peer_role}_public_identity_key.json"
    try:
        with open(filename, 'w') as f:
            json.dump({'public_key_pem': public_key_pem_str}, f, indent=2)
        logging.info(f"Successfully wrote peer's public key to {filename}.")
    except Exception as e:
        logging.error(f"Error writing peer's public key to {filename}: {e}")

async def load_or_generate_identity_keys():
    """Loads identity keys from file or generates new ones."""
    global identity_key_pair
    if os.path.exists(IDENTITY_KEY_FILE):
        logging.info(f"Loading {ROLE} identity keys from {IDENTITY_KEY_FILE}...")
        with open(IDENTITY_KEY_FILE, 'r') as f:
            keys_data = json.load(f)
            private_pem = keys_data['private_key']
            public_pem = keys_data['public_key']
            identity_key_pair = (
                import_private_key_from_pem_str(private_pem),
                import_public_key_from_pem_str(public_pem)
            )
        logging.info(f"{ROLE} identity keys loaded.")
    else:
        logging.info(f"Generating new {ROLE} identity keys...")
        private_key, public_key = await generate_identity_key_pair()
        identity_key_pair = (private_key, public_key)
        with open(IDENTITY_KEY_FILE, 'w') as f:
            json.dump({
                'private_key': export_private_key_to_pem_str(private_key),
                'public_key': export_public_key_to_pem_str(public_key)
            }, f, indent=2)
        logging.info(f"New {ROLE} identity keys generated and saved to {IDENTITY_KEY_FILE}.")
    
    # Display public key for manual exchange
    logging.info(f"\n--- Your {ROLE} Public Identity Key (Share with Peer) ---")
    public_pem_str_display = export_public_key_to_pem_str(identity_key_pair[1])
    logging.info(public_pem_str_display)
    # Print public key in hex for easy comparison
    logging.info(f"Your {ROLE} Public Key HEX (for comparison): {public_key_to_hex_bytes(identity_key_pair[1])}")
    logging.info(f"----------------------------------------------------\n")

async def load_peer_public_key():
    """
    Loads the peer's public identity key from file.
    No longer exits if not found, as it will be created automatically later.
    """
    global peer_public_identity_key
    if os.path.exists(PEER_PUBLIC_KEY_FILE):
        logging.info(f"Loading peer's public identity key from {PEER_PUBLIC_KEY_FILE}...")
        try:
            with open(PEER_PUBLIC_KEY_FILE, 'r') as f:
                # Load the JSON object, then extract the PEM string
                peer_key_data = json.load(f)
                peer_public_pem_str = peer_key_data['public_key_pem']
                peer_public_identity_key = import_public_key_from_pem_str(peer_public_pem_str)
            logging.info("Peer's public identity key loaded.")
            # Print peer's public key in hex for easy comparison
            logging.info(f"Peer's Public Key HEX (for comparison): {public_key_to_hex_bytes(peer_public_identity_key)}")
        except Exception as e:
            logging.error(f"Error loading or parsing peer's public key from {PEER_PUBLIC_KEY_FILE}: {e}")
            logging.error("Please ensure the file exists and contains a valid JSON object with a 'public_key_pem' field.")
            # Do NOT exit here, allow handshake to proceed to create the file
            peer_public_identity_key = None # Ensure it's explicitly None if load failed
    else:
        logging.warning(f"Peer's public identity key file '{PEER_PUBLIC_KEY_FILE}' not found.")
        logging.warning(f"This file will be created automatically after the first successful ECDH handshake with the peer.")
        peer_public_identity_key = None # Ensure it's explicitly None if file is missing

# --- Communication Logic ---

async def send_encrypted_message(websocket, plaintext: str, message_type: str = "real"):
    """
    Encrypts, signs, and sends a message.
    The payload is now variable size (no fixed padding).
    """
    global shared_session_key, identity_key_pair, my_session_id, peer_session_id

    if not shared_session_key:
        logging.error("Session key not established. Cannot send message.")
        return False
    if not identity_key_pair:
        logging.error("Identity keys not loaded. Cannot send message.")
        return False
    if not my_session_id or not peer_session_id:
        logging.error("Session IDs not set. Cannot send message.")
        return False
    # Added check: cannot send signed messages if peer's public key isn't loaded/saved
    if peer_public_identity_key is None and message_type != "ECDH_HANDSHAKE_INIT": # Allow initial handshake without peer key loaded
        logging.error("Peer's public identity key not available. Cannot send signed messages (unless it's an initial handshake).")
        return False

    try:
        # 1. Prepare internal message JSON (includes sender/receiver IDs)
        internal_message = {
            "from": my_session_id, # Use session ID as internal identifier
            "to": peer_session_id, # Use peer's session ID as internal identifier
            "type": message_type,
            "timestamp": time.time(),
            "content": plaintext
        }
        internal_message_bytes = json.dumps(internal_message).encode('utf-8')

        # 2. No padding - plaintext_bytes is the direct input to encryption
        plaintext_for_encryption = internal_message_bytes

        # 3. Generate Nonce
        nonce = os.urandom(16) # 16 bytes for AES-GCM nonce

        # 4. Encrypt message (produces ciphertext and tag)
        ciphertext, tag = encrypt_message(shared_session_key, plaintext_for_encryption, nonce)
        
        # Store ciphertext length for the receiver to parse the variable payload
        ciphertext_length = len(ciphertext)

        # 5. Concatenate components for signing (Nonce || Ciphertext || Tag)
        data_to_sign = nonce + ciphertext + tag

        # --- NEW DEBUG PRINTS FOR SENDER ---
        logging.debug(f"SENDER: Nonce ({len(nonce)} bytes): {nonce.hex()}")
        logging.debug(f"SENDER: Ciphertext ({len(ciphertext)} bytes): {ciphertext.hex()}")
        logging.debug(f"SENDER: Tag ({len(tag)} bytes): {tag.hex()}")
        logging.debug(f"SENDER: Data to sign ({len(data_to_sign)} bytes): {data_to_sign.hex()}") # FULL HEX
        # --- END DEBUG PRINTS ---

        # 6. Sign the concatenated data
        signature = sign_data(identity_key_pair[0], data_to_sign)

        # 7. Assemble the variable-size encrypted payload
        # The order is crucial: Nonce, Ciphertext, Tag, Signature
        encrypted_payload_binary = nonce + ciphertext + tag + signature

        # 8. Base64 encode the binary payload for JSON transport
        encrypted_payload_b66 = bytes_to_base64(encrypted_payload_binary)

        # 9. Construct the outer message packet for the server
        # Include ciphertext_length for receiver to parse the variable payload
        outer_packet = {
            "source_session_id": my_session_id,
            "destination_session_id": peer_session_id,
            "type": "encrypted_message", # Explicit type for encrypted messages
            "encrypted_payload": encrypted_payload_b66,
            "ciphertext_length": ciphertext_length # New: Include length for variable payload parsing
        }

        await websocket.send(json.dumps(outer_packet))
        logging.info(f"Sent {message_type} message (variable size) to {peer_session_id}.")
        return True

    except ValueError as e:
        logging.error(f"Error sending message (value issue): {e}")
        return False
    except Exception as e:
        logging.error(f"Error sending message: {e}")
        return False

async def handle_incoming_message(websocket, message_json):
    """
    Handles an incoming message from the server.
    This includes session_id assignment, ECDH key exchange, and encrypted messages.
    """
    global my_session_id, peer_session_id, ephemeral_key_pair, shared_session_key, seen_nonces, peer_public_identity_key

    msg_type = message_json.get("type")
    source_session = message_json.get("source_session_id") # Get source_session for logging/response

    if msg_type == "session_id":
        my_session_id = message_json.get("session_id")
        logging.info(f"Received my session ID from server: {my_session_id}")
        
        # This input is blocking, better handled by a separate input loop or initial prompt
        # For PoC simplicity, we keep it here.
        await asyncio.to_thread(lambda: sys.stdout.write(f"Please enter the peer's session ID (from their client output) and press Enter: "))
        peer_session_id_input = await asyncio.to_thread(sys.stdin.readline)
        peer_session_id = peer_session_id_input.strip() # Remove newline character
        logging.info(f"Peer session ID set to: {peer_session_id}")
        
        # Initiate ECDH handshake by sending our ephemeral public key
        ephemeral_key_pair = await generate_ephemeral_key_pair()
        ephemeral_public_key_pem = export_public_key_to_pem_str(ephemeral_key_pair[1])
        
        handshake_packet = {
            "source_session_id": my_session_id,
            "destination_session_id": peer_session_id,
            "type": "ECDH_HANDSHAKE_INIT",
            "ephemeral_public_key": ephemeral_public_key_pem,
            "identity_public_key": export_public_key_to_pem_str(identity_key_pair[1]) # Send our identity public key
        }
        await websocket.send(json.dumps(handshake_packet))
        logging.info(f"Sent ECDH handshake init to {peer_session_id}.")

    elif msg_type == "ECDH_HANDSHAKE_INIT":
        if shared_session_key:
            logging.warning("Received ECDH_HANDSHAKE_INIT but session key already established. Ignoring.")
            return

        peer_ephemeral_public_key_pem = message_json.get("ephemeral_public_key")
        peer_identity_public_key_pem = message_json.get("identity_public_key") # Get peer's identity public key

        if not peer_identity_public_key_pem:
            logging.error("Received ECDH_HANDSHAKE_INIT without peer's identity public key. Message rejected.")
            return

        # NEW: Load and save peer's identity public key
        try:
            peer_public_identity_key = import_public_key_from_pem_str(peer_identity_public_key_pem)
            # Write it to file for future runs
            # Determine the correct filename based on the current client's role
            target_peer_role_for_file = 'bank' if ROLE == 'customer' else 'customer'
            write_peer_public_key_to_file(target_peer_role_for_file, peer_identity_public_key_pem)
            logging.info(f"Successfully received and saved peer's identity public key from {source_session}.")
            logging.info(f"Peer's Public Key HEX (for comparison): {public_key_to_hex_bytes(peer_public_identity_key)}")
        except Exception as e:
            logging.error(f"Error importing peer's identity public key during handshake: {e}. Message rejected.")
            return

        # Generate our ephemeral key pair if not already done (e.g., if we are responder)
        if not ephemeral_key_pair:
            ephemeral_key_pair = await generate_ephemeral_key_pair()

        # Verify the signature of the handshake message itself (optional but good)
        # For simplicity of this PoC, we are not signing the handshake message itself,
        # but relying on the fact that identity_public_key is sent within the trusted WSS channel.
        # In a real system, handshake messages would also be signed.

        try:
            peer_ephemeral_public_key = import_public_key_from_pem_str(peer_ephemeral_public_key_pem)
        except Exception as e:
            logging.error(f"Error importing peer's ephemeral public key for handshake: {e}. Message rejected.")
            return

        # Derive shared secret
        shared_session_key_bytes = await derive_shared_secret(ephemeral_key_pair[0], peer_ephemeral_public_key)
        shared_session_key = shared_session_key_bytes # Store the derived key bytes

        logging.info("Derived shared session key.")

        # Send our ephemeral public key back as response to complete handshake
        ephemeral_public_key_pem = export_public_key_to_pem_str(ephemeral_key_pair[1])
        handshake_response_packet = {
            "source_session_id": my_session_id,
            "destination_session_id": source_session, # Respond to initiator
            "type": "ECDH_HANDSHAKE_RESPONSE",
            "ephemeral_public_key": ephemeral_public_key_pem,
            "identity_public_key": export_public_key_to_pem_str(identity_key_pair[1]) # Send our identity public key
        }
        await websocket.send(json.dumps(handshake_packet))
        logging.info(f"Sent ECDH handshake response to {source_session}. Session established.")

    elif msg_type == "ECDH_HANDSHAKE_RESPONSE":
        if shared_session_key:
            logging.warning("Received ECDH_HANDSHAKE_RESPONSE but session key already established. Ignoring.")
            return
        
        peer_ephemeral_public_key_pem = message_json.get("ephemeral_public_key")
        peer_identity_public_key_pem = message_json.get("identity_public_key") # Get peer's identity public key

        if not peer_identity_public_key_pem:
            logging.error("Received ECDH_HANDSHAKE_RESPONSE without peer's identity public key. Message rejected.")
            return

        # NEW: Load and save peer's identity public key
        try:
            peer_public_identity_key = import_public_key_from_pem_str(peer_identity_public_key_pem)
            # Write it to file for future runs
            # Determine the correct filename based on the current client's role
            target_peer_role_for_file = 'bank' if ROLE == 'customer' else 'customer'
            write_peer_public_key_to_file(target_peer_role_for_file, peer_identity_public_key_pem)
            logging.info(f"Successfully received and saved peer's identity public key from {source_session}.")
            logging.info(f"Peer's Public Key HEX (for comparison): {public_key_to_hex_bytes(peer_public_identity_key)}")
        except Exception as e:
            logging.error(f"Error importing peer's identity public key during handshake response: {e}. Message rejected.")
            return

        try:
            peer_ephemeral_public_key = import_public_key_from_pem_str(peer_ephemeral_public_key_pem)
        except Exception as e:
            logging.error(f"Error importing peer's ephemeral public key for handshake response: {e}. Message rejected.")
            return

        # Derive shared secret
        shared_session_key_bytes = await derive_shared_secret(ephemeral_key_pair[0], peer_ephemeral_public_key)
        shared_session_key = shared_session_key_bytes # Store the derived key bytes
        logging.info("Derived shared session key. Session established.")

    elif msg_type == "encrypted_message": # This is a regular encrypted message
        # Check if peer_public_identity_key is available (it should be after handshake)
        if peer_public_identity_key is None:
            logging.error("Peer's public identity key is NOT loaded. Cannot verify messages. This indicates a handshake failure or file deletion.")
            return # Cannot proceed without peer's public key for verification

        if not shared_session_key:
            logging.error("Session key not established. Cannot process encrypted message.")
            return

        encrypted_payload_b64 = message_json["encrypted_payload"]
        ciphertext_length = message_json.get("ciphertext_length") # Get ciphertext_length from the packet

        if ciphertext_length is None:
            logging.warning("Received encrypted message without ciphertext_length. Dropping.")
            return

        try:
            encrypted_payload_binary = base64_to_bytes(encrypted_payload_b64)

            # Parse the VARIABLE-SIZE binary payload using ciphertext_length
            nonce = encrypted_payload_binary[0:16]
            ciphertext = encrypted_payload_binary[16 : 16 + ciphertext_length]
            tag = encrypted_payload_binary[16 + ciphertext_length : 16 + ciphertext_length + 16]
            signature = encrypted_payload_binary[16 + ciphertext_length + 16 : ] # Slice to the end for signature
            
            # --- NEW DEBUG PRINTS FOR RECEIVER ---
            logging.debug(f"RECEIVER: Nonce ({len(nonce)} bytes): {nonce.hex()}")
            logging.debug(f"RECEIVER: Ciphertext ({len(ciphertext)} bytes): {ciphertext.hex()}")
            logging.debug(f"RECEIVER: Tag ({len(tag)} bytes): {tag.hex()}")
            logging.debug(f"RECEIVER: Signature ({len(signature)} bytes): {signature.hex()}")
            data_to_verify = nonce + ciphertext + tag
            logging.debug(f"RECEIVER: Data to verify ({len(data_to_verify)} bytes): {data_to_verify.hex()}") # FULL HEX
            # --- END DEBUG PRINTS ---

            # 1. Verify Signature (Authenticity)
            try:
                verify_signature(peer_public_identity_key, data_to_verify, signature)
                logging.info("Signature verified successfully.")
            except InvalidSignature:
                logging.error(f"Signature verification failed: InvalidSignature. Message rejected.")
                return # Stop processing this message
            except Exception as e:
                logging.error(f"Signature verification failed: {e}. Message rejected.")
                return # Stop processing this message

            # 2. Check Nonce (Replay Protection)
            nonce_b64 = bytes_to_base64(nonce)
            if nonce_b64 in seen_nonces:
                logging.warning("Replay attack detected! Nonce already seen. Message rejected.")
                return
            seen_nonces.add(nonce_b64)

            # 3. Decrypt Message (Confidentiality & Integrity)
            try:
                # This will now be the raw decrypted JSON bytes
                decrypted_internal_message_bytes = decrypt_message(shared_session_key, ciphertext, nonce, tag)
                
                # Directly decode the JSON bytes
                internal_message = json.loads(decrypted_internal_message_bytes.decode('utf-8'))

                if internal_message.get("type") == "dummy":
                    logging.info(f"Received dummy message from {internal_message.get('from')}. Discarding.")
                else:
                    # --- START NEW FORMATTING ---
                    peer_session_id_display = internal_message.get('from', 'UNKNOWN_SENDER')
                    message_content = internal_message.get('content', 'N/A')
                    timestamp_float = internal_message.get('timestamp', time.time())
                    timestamp_formatted = datetime.fromtimestamp(timestamp_float).strftime('%Y-%m-%d %H:%M:%S')

                    print("\n" + "-" * 50)
                    print(f"| Received Message from  : {peer_session_id_display}")
                    print(f"| Message                : {message_content}")
                    print(f"| Timestamp              : {timestamp_formatted}")
                    print("-" * 50 + "\n")
                    # --- END NEW FORMATTING ---

            except InvalidTag:
                logging.error(f"Decryption or integrity check failed: InvalidTag. Message rejected (tampered or wrong key).")
                return
            except json.JSONDecodeError as e:
                logging.error(f"JSON decoding failed after decryption: {e}. Raw decrypted bytes: {decrypted_internal_message_bytes[:100]}...")
                return
            except UnicodeDecodeError as e:
                logging.error(f"Unicode decoding failed after decryption: {e}. Raw decrypted bytes: {decrypted_internal_message_bytes[:100]}...")
                return
            except Exception as e:
                logging.error(f"Unexpected error during internal message parsing: {e}")
                return

        except Exception as e:
            logging.error(f"Error processing encrypted payload: {e}. Message dropped.")
            return
    else:
        logging.warning(f"Unknown message type received: {message_json.get('type')}")


async def receive_loop(websocket):
    """Listens for incoming messages from the server."""
    try:
        async for message in websocket:
            try:
                message_json = json.loads(message)
                await handle_incoming_message(websocket, message_json)
            except json.JSONDecodeError:
                logging.error(f"Received non-JSON message from server: {message[:100]}...")
            except Exception as e:
                logging.error(f"Error processing server message: {e}")
    except websockets.exceptions.ConnectionClosedOK:
        logging.info("Connection to server closed gracefully.")
    except Exception as e:
        logging.error(f"Connection to server lost: {e}")

async def send_loop(websocket):
    """Handles user input and sends messages."""
    while True:
        if shared_session_key and peer_session_id:
            # Added check for peer_public_identity_key before allowing sending
            if peer_public_identity_key is None:
                logging.warning("Peer's public identity key not yet loaded/saved. Waiting for handshake to complete.")
                await asyncio.sleep(2) # Wait a bit and re-check
                continue

            message = await asyncio.to_thread(input, "Enter message to send (or 'exit'): ")
            if message.lower() == 'exit':
                break
            await send_encrypted_message(websocket, message, "real")
        else:
            await asyncio.sleep(1) # Wait for session to be established

async def dummy_message_loop(websocket):
    """Periodically sends dummy messages."""
    while True:
        if shared_session_key and peer_session_id:
            # Added check for peer_public_identity_key before sending dummy messages
            if peer_public_identity_key is None:
                await asyncio.sleep(5) # Wait if peer's public key not ready
                continue

            interval = random.randint(DUMMY_MESSAGE_INTERVAL_MIN, DUMMY_MESSAGE_INTERVAL_MAX)
            logging.info(f"Next dummy message in {interval} seconds...")
            await asyncio.sleep(interval)
            await send_encrypted_message(websocket, f"Dummy message from {ROLE} at {time.time()}", "dummy")
        else:
            await asyncio.sleep(5) # Wait longer if session not established

async def main():
    """Main function to run the client."""
    await load_or_generate_identity_keys()
    await load_peer_public_key() # This will now attempt to load, but won't exit if file is missing

    # Configure SSL context to trust the self-signed certificate
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
        ssl_context.load_verify_locations('cert.pem') # Trust our self-signed cert
    except FileNotFoundError:
        logging.error("SSL certificate file (cert.pem) not found. Please ensure it's in the same directory.")
        sys.exit(1) # Exit if cert.pem is missing
    
    ssl_context.check_hostname = False # For localhost, can be True for real domains
    ssl_context.verify_mode = ssl.CERT_REQUIRED # Ensure certificate is verified

    logging.info(f"Connecting to {SERVER_URI}...")
    try:
        async with websockets.connect(SERVER_URI, ssl=ssl_context) as websocket:
            logging.info("Connected to server.")
            
            # Run send, receive, and dummy message loops concurrently
            await asyncio.gather(
                send_loop(websocket),
                receive_loop(websocket),
                dummy_message_loop(websocket)
            )
    except websockets.exceptions.InvalidURI as e:
        logging.error(f"Invalid server URI: {e}. Please check SERVER_URI.")
    except ConnectionRefusedError:
        logging.error("Connection refused. Is the server running on wss://localhost:8765?")
    except ssl.SSLCertVerificationError as e:
        logging.error(f"SSL certificate verification failed: {e}. Ensure 'cert.pem' is correct and trusted.")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    asyncio.run(main())
