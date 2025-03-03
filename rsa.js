const express = require("express");
const {
  generateKeyPairSync,
  publicEncrypt,
  privateDecrypt,
} = require("crypto");
const app = express();
const port = 3000;

app.use(express.static("public"));

app.get("/generate", (req, res) => {
  const modulusLength = parseInt(req.query.modulusLength) || 2048;
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: modulusLength,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  res.json({ publicKey, privateKey });
});

app.get("/", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>RSA Key Generator</title>
        <style>
            body { font-family: Arial, sans-serif; background: #f4f4f4; padding: 20px; }
            .container { display: flex; gap: 20px; }
            .column { width: 50%; padding: 20px; background: white; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
            h3 { color: #333; }
            textarea, select, button { width: 100%; margin-top: 10px; padding: 10px; font-size: 16px; border: 1px solid #ccc; border-radius: 5px; }
            button { background: #007bff; color: white; border: none; cursor: pointer; }
            button:hover { background: #0056b3; }
        </style>
    </head>
    <body>
        <h2 style="text-align:center;">RSA Key Generator</h2>
        <div class="container">
            <div class="column">
                <h3>Generate Keys</h3>
                <label for="modulusLength">Modulus Length:</label>
                <select id="modulusLength">
                    <option value="1024">1024</option>
                    <option value="2048" selected>2048</option>
                    <option value="4096">4096</option>
                </select>
                <button onclick="generateKeys()">Generate RSA Keys</button>
                <h3>Public Key:</h3>
                <textarea id="publicKey" rows="6" readonly></textarea>
                <h3>Private Key:</h3>
                <textarea id="privateKey" rows="6" readonly></textarea>
            </div>
            <div class="column">
                <h3>Encrypt & Decrypt</h3>
                <textarea id="inputText" rows="3" placeholder="Enter text to encrypt..."></textarea>
                <button onclick="encryptText()">Encrypt</button>
                <h3>Encrypted Text:</h3>
                <textarea id="encryptedText" rows="3" readonly></textarea>
                <button onclick="decryptText()">Decrypt</button>
                <h3>Decrypted Text:</h3>
                <textarea id="decryptedText" rows="3" readonly></textarea>
            </div>
        </div>
        <script>
            let publicKey = "";
            let privateKey = "";

            function generateKeys() {
                const modulusLength = document.getElementById("modulusLength").value;
                fetch("/generate?modulusLength=" + modulusLength)
                    .then(response => response.json())
                    .then(data => {
                        publicKey = data.publicKey;
                        privateKey = data.privateKey;
                        document.getElementById("publicKey").value = data.publicKey;
                        document.getElementById("privateKey").value = data.privateKey;
                    });
            }

            function encryptText() {
                const text = document.getElementById("inputText").value;
                if (!publicKey || !text) {
                    alert("Generate keys first and enter text to encrypt.");
                    return;
                }
                fetch("/encrypt", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ text, publicKey })
                })
                .then(response => response.json())
                .then(data => {
                    document.getElementById("encryptedText").value = data.encrypted;
                });
            }

            function decryptText() {
                const encrypted = document.getElementById("encryptedText").value;
                if (!privateKey || !encrypted) {
                    alert("Generate keys first and encrypt text before decrypting.");
                    return;
                }
                fetch("/decrypt", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ encrypted, privateKey })
                })
                .then(response => response.json())
                .then(data => {
                    document.getElementById("decryptedText").value = data.decrypted;
                });
            }
        </script>
    </body>
    </html>
    `);
});

app.use(express.json());

app.post("/encrypt", (req, res) => {
  const { text, publicKey } = req.body;
  const buffer = Buffer.from(text, "utf8");
  const encrypted = publicEncrypt(publicKey, buffer).toString("base64");
  res.json({ encrypted });
});

app.post("/decrypt", (req, res) => {
  const { encrypted, privateKey } = req.body;
  const buffer = Buffer.from(encrypted, "base64");
  const decrypted = privateDecrypt(privateKey, buffer).toString("utf8");
  res.json({ decrypted });
});

app.listen(port, () => {
  console.log(`RSA Key Generator running at http://localhost:${port}`);
});
