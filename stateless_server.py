# stateless_server.py
import asyncio
import websockets
import ssl
import json
import uuid
import logging
import base64 # Import base64 for potential future use or debugging, though not strictly needed for this fix

logging.basicConfig(level=logging.INFO)

# Dictionary to store active WebSocket connections, mapped by their session_id
CONNECTED_CLIENTS = {}

# Fixed size for the encrypted payload (Nonce + Ciphertext + Tag + Signature)
# This constant is no longer used for size validation since padding is removed.
# It's commented out to avoid confusion.
# FIXED_ENCRYPTED_PAYLOAD_BINARY_SIZE = 608 # 608 bytes

async def handler(websocket, path=None): # Make 'path' optional with a default of None
    """
    Handles a new WebSocket connection from a client.
    Assigns a session ID and relays messages.
    """
    if path is None:
        logging.warning("`path` argument was not provided by websockets. Assuming root path '/'.")
        path = "/"

    session_id = str(uuid.uuid4())
    CONNECTED_CLIENTS[session_id] = websocket
    logging.info(f"Client connected: {session_id} on path {path}. Total connected: {len(CONNECTED_CLIENTS)}")

    try:
        # Send the assigned session_id to the client
        await websocket.send(json.dumps({"type": "session_id", "session_id": session_id}))
        logging.info(f"Sent session_id {session_id} to client.")

        async for message in websocket:
            try:
                data = json.loads(message)

                source_session = data.get("source_session_id")
                destination_session = data.get("destination_session_id")
                message_type = data.get("type") # Get the message type

                # --- NEW LOGIC HERE ---
                if message_type in ["ECDH_HANDSHAKE_INIT", "ECDH_HANDSHAKE_RESPONSE"]:
                    # These are handshake messages, they don't have 'encrypted_payload'
                    if not all([source_session, destination_session, message_type, data.get("ephemeral_public_key")]):
                        logging.warning(f"Malformed handshake message received from {source_session}: {data}")
                        continue
                    # Relay handshake messages as is
                    logging.info(f"Relaying {message_type} from {source_session} to {destination_session}.")
                    destination_websocket = CONNECTED_CLIENTS.get(destination_session)
                    if destination_websocket:
                        await destination_websocket.send(message)
                        logging.info(f"Handshake message relayed successfully to {destination_session}.")
                    else:
                        logging.warning(f"Destination client {destination_session} not found for handshake. Message dropped.")
                    continue # Finished handling handshake message

                elif message_type == "encrypted_message": # This is a regular encrypted message
                    # This is a regular encrypted message, it MUST have 'encrypted_payload'
                    # and 'ciphertext_length' (for the receiver to parse variable payload)
                    encrypted_payload_b64 = data.get("encrypted_payload")
                    ciphertext_length = data.get("ciphertext_length") # New: Get ciphertext_length from packet

                    if not all([source_session, destination_session, encrypted_payload_b64, ciphertext_length is not None]):
                        logging.warning(f"Malformed encrypted message received from {source_session}: {data}")
                        continue

                    # --- REMOVE THIS ENTIRE BLOCK OF SIZE CHECKS ---
                    # The server no longer validates payload size as clients send variable lengths.
                    # This was the section causing the "Expected approx 808 but got..." warning.
                    #
                    # expected_b64_len = (FIXED_ENCRYPTED_PAYLOAD_BINARY_SIZE // 3) * 4
                    # if len(encrypted_payload_b64) < expected_b64_len or len(encrypted_payload_b64) > expected_b64_len + 4:
                    #      logging.warning(f"Received payload with incorrect Base64 size from {source_session}. Expected approx {expected_b64_len} but got {len(encrypted_payload_b64)}")
                    #      continue
                    # --- END REMOVAL ---

                    logging.info(f"Relaying encrypted message from {source_session} to {destination_session}.")
                    destination_websocket = CONNECTED_CLIENTS.get(destination_session)
                    if destination_websocket:
                        await destination_websocket.send(message)
                        logging.info(f"Encrypted message relayed successfully to {destination_session}.")
                    else:
                        logging.warning(f"Destination client {destination_session} not found for encrypted message. Message dropped.")
                    continue # Finished handling encrypted message

                else:
                    logging.warning(f"Received unhandled message type '{message_type}' from {source_session}: {data}")
                    # You might want to drop or log unhandled types
                    continue
                # --- END NEW LOGIC ---

            except json.JSONDecodeError:
                logging.error(f"Received non-JSON message from {session_id}: {message[:100]}...")
            except Exception as e:
                logging.error(f"Error handling message from {session_id}: {e}")

    except websockets.exceptions.ConnectionClosedOK:
        logging.info(f"Client {session_id} disconnected gracefully.")
    except Exception as e:
        logging.error(f"Client {session_id} disconnected with error: {e}")
    finally:
        # Clean up the connection
        if session_id in CONNECTED_CLIENTS:
            del CONNECTED_CLIENTS[session_id]
            logging.info(f"Client {session_id} removed. Total connected: {len(CONNECTED_CLIENTS)}")

async def main():
    """Starts the WebSocket server."""
    # Configure SSL context
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        ssl_context.load_cert_chain('cert.pem', 'key.pem')
    except FileNotFoundError:
        logging.error("SSL certificate files (cert.pem, key.pem) not found. Please generate them.")
        logging.error("Run: openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365 -subj '/CN=localhost'")
        return

    logging.info("Starting WebSocket server on wss://localhost:8765")
    async with websockets.serve(handler, "localhost", 8765, ssl=ssl_context):
        await asyncio.Future() # Run forever

if __name__ == "__main__":
    asyncio.run(main())
