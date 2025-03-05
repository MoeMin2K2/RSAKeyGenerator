const express = require("express");
const forge = require("node-forge");
const cors = require("cors");
const bodyParser = require("body-parser");

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Helper function to format base64 key into PEM format
function formatPem(key, type) {
  if (key.includes("-----BEGIN")) return key;
  const header = `-----BEGIN ${type} KEY-----\n`;
  const footer = `\n-----END ${type} KEY-----`;
  return header + key.match(/.{1,64}/g).join("\n") + footer;
}

// Encrypt Message
app.post("/encrypt", (req, res) => {
  const { publicKey, message } = req.body;
  try {
    const formattedKey = formatPem(publicKey, "PUBLIC");
    const rsa = forge.pki.publicKeyFromPem(formattedKey);
    const encrypted = rsa.encrypt(
      forge.util.encodeUtf8(message),
      "RSAES-PKCS1-V1_5"
    );
    res.json({ encrypted: forge.util.encode64(encrypted) });
  } catch (error) {
    res.status(400).json({ error: "Encryption failed! Invalid public key." });
  }
});

// Decrypt Message
app.post("/decrypt", (req, res) => {
  const { privateKey, encrypted } = req.body;
  try {
    const formattedKey = formatPem(privateKey, "PRIVATE");
    const rsa = forge.pki.privateKeyFromPem(formattedKey);
    const decrypted = rsa.decrypt(
      forge.util.decode64(encrypted),
      "RSAES-PKCS1-V1_5"
    );
    res.json({ decrypted: forge.util.decodeUtf8(decrypted) });
  } catch (error) {
    res
      .status(400)
      .json({ error: "Decryption failed! Invalid private key or ciphertext." });
  }
});

// Serve HTML page
app.get("/", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>RSA Encrypt & Decrypt</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                text-align: center;
                background: #f4f4f4;
                padding: 20px;
            }
            .container {
                max-width: 600px;
                margin: auto;
                background: white;
                padding: 20px;
                border-radius: 10px;
                box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
            }
            textarea, button {
                width: 100%;
                margin-top: 10px;
                padding: 10px;
                font-size: 14px;
                border-radius: 5px;
                border: 1px solid #ccc;
                box-sizing: border-box;
            }
            button {
                background: #007BFF;
                color: white;
                border: none;
                cursor: pointer;
                font-weight: bold;
                transition: 0.3s;
            }
            button:hover {
                background: #0056b3;
            }
            h2 {
                margin-bottom: 20px;
            }
            .input-container {
                text-align: left;
                margin-top: 10px;
            }
            label {
                font-weight: bold;
            }
            .output {
                background: #e9ecef;
                padding: 10px;
                border-radius: 5px;
                word-wrap: break-word;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>RSA Encryption & Decryption</h2>
            
            <div class="input-container">
                <label>Public Key (Paste Base64 or PEM Format)</label>
                <textarea id="publicKey" rows="6" placeholder="Paste your RSA Public Key"></textarea>
            </div>

            <div class="input-container">
                <label>Message</label>
                <textarea id="message" rows="2" placeholder="Enter text to encrypt"></textarea>
            </div>

            <button onclick="encryptMessage()">Encrypt</button>

            <div class="input-container">
                <label>Encrypted Output</label>
                <textarea id="encrypted" rows="4" class="output" readonly></textarea>
            </div>

            <hr>

            <div class="input-container">
                <label>Private Key (Paste Base64 or PEM Format)</label>
                <textarea id="privateKey" rows="6" placeholder="Paste your RSA Private Key"></textarea>
            </div>

            <div class="input-container">
                <label>Encrypted Message</label>
                <textarea id="decryptInput" rows="4" placeholder="Paste encrypted text"></textarea>
            </div>

            <button onclick="decryptMessage()">Decrypt</button>

            <div class="input-container">
                <label>Decrypted Message</label>
                <textarea id="decryptedMessage" rows="2" class="output" readonly></textarea>
            </div>
        </div>

        <script>
            async function encryptMessage() {
                const publicKey = document.getElementById("publicKey").value.trim();
                const message = document.getElementById("message").value.trim();
                if (!publicKey || !message) {
                    alert("Please enter both public key and message.");
                    return;
                }
                try {
                    const res = await fetch('/encrypt', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ publicKey, message })
                    });
                    const data = await res.json();
                    if (data.encrypted) {
                        document.getElementById("encrypted").value = data.encrypted;
                    } else {
                        throw new Error(data.error);
                    }
                } catch (error) {
                    alert("Encryption failed! " + error.message);
                }
            }

            async function decryptMessage() {
                const privateKey = document.getElementById("privateKey").value.trim();
                const encrypted = document.getElementById("decryptInput").value.trim();
                if (!privateKey || !encrypted) {
                    alert("Please enter both private key and encrypted message.");
                    return;
                }
                try {
                    const res = await fetch('/decrypt', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ privateKey, encrypted })
                    });
                    const data = await res.json();
                    if (data.decrypted) {
                        document.getElementById("decryptedMessage").value = data.decrypted;
                    } else {
                        throw new Error(data.error);
                    }
                } catch (error) {
                    alert("Decryption failed! " + error.message);
                }
            }
        </script>
    </body>
    </html>
  `);
});

app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});
