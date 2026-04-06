#!/usr/bin/env node
/**
 * Build script: encrypts dashboard.html with a password using AES-256-GCM + PBKDF2.
 * The output index.html is a login page that decrypts client-side.
 * Usage: node build.js [password]
 * Default password: portfolio
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PASSWORD = process.argv[2] || 'portfolio';
const SALT_LEN = 16;
const IV_LEN = 12;
const ITERATIONS = 100000;

// Read dashboard source
const dashboardHtml = fs.readFileSync(path.join(__dirname, 'dashboard.html'), 'utf8');

// Encrypt
const salt = crypto.randomBytes(SALT_LEN);
const iv = crypto.randomBytes(IV_LEN);
const key = crypto.pbkdf2Sync(PASSWORD, salt, ITERATIONS, 32, 'sha256');
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
let encrypted = cipher.update(dashboardHtml, 'utf8', 'base64');
encrypted += cipher.final('base64');
const tag = cipher.getAuthTag().toString('base64');

// Payload: salt:iv:tag:ciphertext (all base64)
const payload = [salt.toString('base64'), iv.toString('base64'), tag, encrypted].join(':');

// Build the login page
const loginPage = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>Portfolio</title>
<link rel="manifest" href="manifest.json">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="theme-color" content="#0a0a12">
<link rel="apple-touch-icon" href="icon-192.png">
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;900&display=swap');
  *{margin:0;padding:0;box-sizing:border-box;}
  body{font-family:'Inter',-apple-system,sans-serif;background:#0a0a12;color:#e4e4f0;min-height:100vh;display:flex;align-items:center;justify-content:center;
    background-image:radial-gradient(ellipse at 20% 50%,rgba(124,58,237,0.05) 0%,transparent 50%),radial-gradient(ellipse at 80% 50%,rgba(0,229,255,0.03) 0%,transparent 50%);}
  .login-box{background:#111120;border:1px solid #2a2a44;border-radius:20px;padding:40px;width:380px;max-width:90vw;text-align:center;position:relative;overflow:hidden;}
  .login-box::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,#7c3aed,#b388ff,#00e5ff);}
  .avatar{width:64px;height:64px;border-radius:16px;background:linear-gradient(135deg,#b388ff,#00e5ff);display:flex;align-items:center;justify-content:center;font-size:28px;font-weight:700;color:#fff;margin:0 auto 20px;box-shadow:0 0 20px rgba(179,136,255,0.3);}
  h1{font-size:22px;font-weight:700;margin-bottom:6px;}
  h1 span{color:#b388ff;}
  .sub{color:#7878a0;font-size:12px;margin-bottom:28px;}
  input{width:100%;padding:14px 16px;background:#1a1a2e;border:1px solid #2a2a44;border-radius:10px;color:#e4e4f0;font-size:14px;outline:none;text-align:center;letter-spacing:2px;}
  input:focus{border-color:#b388ff;box-shadow:0 0 15px rgba(179,136,255,0.15);}
  input::placeholder{letter-spacing:0;color:#7878a0;}
  button{width:100%;margin-top:16px;padding:14px;background:linear-gradient(135deg,#7c3aed,#b388ff);border:none;border-radius:10px;color:#fff;font-size:14px;font-weight:700;cursor:pointer;text-transform:uppercase;letter-spacing:1px;}
  button:hover{opacity:0.9;}
  .err{color:#ff4d6a;font-size:12px;margin-top:12px;min-height:18px;}
  .spinner{display:none;margin:16px auto 0;width:24px;height:24px;border:3px solid #2a2a44;border-top-color:#b388ff;border-radius:50%;animation:spin 0.6s linear infinite;}
  @keyframes spin{to{transform:rotate(360deg);}}
</style>
</head>
<body>
<div class="login-box" id="login-box">
  <div class="avatar">A</div>
  <h1>Artemis <span>Portfolio</span></h1>
  <div class="sub">Enter password to continue</div>
  <form onsubmit="unlock(event)">
    <input type="password" id="pw" placeholder="Password" autofocus autocomplete="off">
    <button type="submit" id="btn">Unlock</button>
  </form>
  <div class="err" id="err"></div>
  <div class="spinner" id="spin"></div>
</div>

<script>
const PAYLOAD = '${payload}';
const ITERATIONS = ${ITERATIONS};

async function unlock(e) {
  e.preventDefault();
  const pw = document.getElementById('pw').value;
  if (!pw) return;
  document.getElementById('btn').style.display = 'none';
  document.getElementById('spin').style.display = 'block';
  document.getElementById('err').textContent = '';
  try {
    const [saltB64, ivB64, tagB64, cipherB64] = PAYLOAD.split(':');
    const salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));
    const iv = Uint8Array.from(atob(ivB64), c => c.charCodeAt(0));
    const tag = Uint8Array.from(atob(tagB64), c => c.charCodeAt(0));
    const cipher = Uint8Array.from(atob(cipherB64), c => c.charCodeAt(0));

    // Combine ciphertext + tag for WebCrypto (it expects them concatenated)
    const combined = new Uint8Array(cipher.length + tag.length);
    combined.set(cipher);
    combined.set(tag, cipher.length);

    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, combined);
    const html = new TextDecoder().decode(decrypted);

    // Remember session
    sessionStorage.setItem('portfolio-unlocked', '1');

    // Replace page
    document.open();
    document.write(html);
    document.close();
  } catch(err) {
    document.getElementById('err').textContent = 'Wrong password';
    document.getElementById('btn').style.display = '';
    document.getElementById('spin').style.display = 'none';
    document.getElementById('pw').value = '';
    document.getElementById('pw').focus();
  }
}

// Auto-unlock if session still valid (same tab)
if (sessionStorage.getItem('portfolio-unlocked')) {
  // They already unlocked this session, but we still need the password to decrypt.
  // Can't bypass. That's by design.
}
</script>
</body>
</html>`;

fs.writeFileSync(path.join(__dirname, 'index.html'), loginPage);
console.log(`Built index.html (encrypted with password: "${PASSWORD}")`);
console.log(`Payload size: ${(payload.length / 1024).toFixed(1)} KB`);
