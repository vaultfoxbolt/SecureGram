# SecureGram 🔒

SecureGram ek **Telegram jaisa web messenger** hai. Isme aap text messages ke saath **photo aur video** bhi share kar sakte ho.

## End-to-End Encryption (E2EE)
- Saare messages aur photos/videos **aapke browser me hi encrypt** hote hain.
- Har user ka browser ek **ECDH P-256** keypair banata hai; dono users ke beech ek shared **AES-GCM (256-bit)** key banti hai.
- Server ke paas sirf **ciphertext** (encrypted data) store hota hai — server aapke messages ya media padh nahi sakta.

## Kaise chalayein
1. **Node.js** install karo: https://nodejs.org (LTS version).
2. Is folder me terminal kholo aur chalao:
   ```bash
   npm install
   npm start
   ```
3. Browser me kholo: **http://localhost:3000**
4. Sign up karo, dusre user ka username daalo aur chat shuru karo. 📎 button se photo/video bhejo.

> ⚠️ Note: Sirf `index.html` file ko double-click karke kholne se app **kaam nahi karega**, kyunki isko server (`npm start`) chahiye.

Test: server chalu rakh ke `npm test` chalao.

## Limitations (seemayein)
- Keys sirf usi browser me rehti hain — naya device ya browser data clear karne par purane messages decrypt nahi honge.
- Key verification (safety numbers) nahi hai, aur forward secrecy nahi hai.
- Server metadata dekh sakta hai (kaun kisse kab baat kar raha hai, file size).
- Internet pe deploy karne ke liye HTTPS zaroori hai.
- Simple JSON-file database; groups aur notifications nahi hain.
