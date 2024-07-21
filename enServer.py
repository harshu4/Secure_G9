import asyncio
import websockets
import json
import logging

logging.basicConfig(level=logging.DEBUG)

IP_CONFIG_FILE = "new_ip_config.json"
CHECK_INTERVAL = 5
OFFLINE_THRESHOLD = 3
RETRY_INTERVAL = 6  # Time in seconds to wait before retrying to connect to servers

# Load IP configuration
with open(IP_CONFIG_FILE, 'r') as f:
    ip_config = json.load(f)

local_server = ip_config['local_server']
SERVER_NAME = local_server['name']
SERVER_PORT = local_server['port']
connected_clients = {}
client_public_keys = {}
client_counter = 0

async def handle_client(websocket, path):
    global client_counter
    client_name = None
    try:
        logging.debug("Client connected")
        async for message in websocket:
            logging.debug(f"Message received: {message}")
            data = json.loads(message)
            if data['tag'] == 'attendance':
                client_counter += 1
                client_name = f'C{client_counter}@{SERVER_NAME}'
                while client_name in connected_clients:
                    client_counter += 1
                    client_name = f'C{client_counter}@{SERVER_NAME}'
                connected_clients[client_name] = websocket
                logging.info(f"New client connected: {client_name}")

                # Send the assigned nickname back to the client
                await websocket.send(json.dumps({
                    "tag": "nickname_assigned",
                    "nickname": client_name
                }))

                # Send all existing public keys to the new client
                await websocket.send(json.dumps({
                    "tag": "existing_public_keys",
                    "public_keys": client_public_keys
                }))

            elif data['tag'] == 'public_key':
                client_public_keys[data['nickname']] = data['public_key']
                await notify_public_key(data['nickname'], data['public_key'])

            elif data['tag'] == 'message':
                await handle_message(data)

            elif data['tag'] == 'presence':
                await handle_presence(data)

            elif data['tag'] == 'broadcast':
                await handle_broadcast(data)

            elif data['tag'] == 'broadcast_key':
                await handle_broadcast_key(data)

            elif data['tag'] == 'file':
                await handle_file(data)

    except websockets.ConnectionClosed:
        logging.info(f"Client {client_name} disconnected")
        if client_name and client_name in connected_clients:
            del connected_clients[client_name]
            del client_public_keys[client_name]

async def handle_message(data):
    recipient = data['to']
    if recipient in connected_clients:
        recipient_websocket = connected_clients[recipient]
        await recipient_websocket.send(json.dumps(data))

async def notify_public_key(nickname, public_key):
    message = json.dumps({
        "tag": "public_key_broadcast",
        "nickname": nickname,
        "public_key": public_key
    })
    await asyncio.gather(*[client.send(message) for client in connected_clients.values()])

async def handle_presence(data):
    for client in data['presence']:
        logging.info(f"Client present: {client['jid']}")
    await asyncio.gather(*[client.send(json.dumps(data)) for client in connected_clients.values()])

async def handle_broadcast(data):
    message = json.dumps(data)
    await asyncio.gather(*[client.send(message) for client in connected_clients.values()])

async def handle_broadcast_key(data):
    message = json.dumps(data)
    await asyncio.gather(*[client.send(message) for client in connected_clients.values()])

async def handle_file(data):
    recipient = data['to']
    if recipient in connected_clients:
        recipient_websocket = connected_clients[recipient]
        await recipient_websocket.send(json.dumps(data))

async def main():
    start_server = websockets.serve(handle_client, local_server['ip'], SERVER_PORT)
    await start_server
    logging.info(f"Server started on {local_server['ip']}:{SERVER_PORT}")
    await asyncio.Future()  # Run forever

# Run the server
asyncio.run(main())
