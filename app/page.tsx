"use client";

import {useState} from "react";

export default function Home() {
    const [encryptData, setEncryptData] = useState("")
    const [plainData, setPlainData] = useState("")
    const [password, setPassword] = useState(() => {
        if (typeof window !== "undefined") {
            return localStorage.getItem("password") || "";
        }
        return "";
    });

    const [url, setUrl] = useState(() => {
        if (typeof window !== "undefined") {
            return localStorage.getItem("url") || "";
        }
        return "";
    });
    const pad = (text) => {
        const blockSize = 16;
        const padding = blockSize - (text.length % blockSize);
        return text + String.fromCharCode(padding).repeat(padding);
    };

    const unpad = (text) => {
        const padding = text.charCodeAt(text.length - 1);
        return text.slice(0, -padding);
    };
    const aesEncrypt = async (password, plaintext) => {
        // Generate AES key from password using PBKDF2
        const key = await deriveKey(password);

        // Create a TextEncoder to encode the text into bytes
        const encoder = new TextEncoder();
        const paddedText = pad(plaintext);
        const data = encoder.encode(paddedText);

        // Encrypt using AES in ECB mode (Web Crypto API does not support ECB, we use AES-CBC instead with a zero IV)
        const iv = new Uint8Array(16); // Zero initialization vector for CBC mode
        const encryptedData = await crypto.subtle.encrypt(
            {
                name: "AES-CBC",
                iv: iv,
            },
            key,
            data
        );

        // Convert the encrypted data to Base64
        return btoa(String.fromCharCode(...new Uint8Array(encryptedData)));
    };

    const aesDecrypt = async (password, ciphertextBase64) => {
        // Generate AES key from password using PBKDF2
        const key = await deriveKey(password);

        // Decode the Base64 ciphertext
        const ciphertext = new Uint8Array(atob(ciphertextBase64).split("").map((c) => c.charCodeAt(0)));

        // Decrypt using AES-CBC with a zero IV
        const iv = new Uint8Array(16); // Zero initialization vector for CBC mode
        const decryptedData = await crypto.subtle.decrypt(
            {
                name: "AES-CBC",
                iv: iv,
            },
            key,
            ciphertext
        );

        // Convert decrypted data to a string
        const decoder = new TextDecoder();
        const decryptedText = decoder.decode(decryptedData);

        // Unpad the decrypted text
        return unpad(decryptedText);
    };
    const deriveKey = async (password) => {
        const encoder = new TextEncoder();
        const passwordBuffer = encoder.encode(password);

        // Use PBKDF2 to derive the AES key from the password
        const keyMaterial = await crypto.subtle.importKey(
            "raw",
            passwordBuffer,
            { name: "PBKDF2" },
            false,
            ["deriveKey"]
        );

        return crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: new TextEncoder().encode("salt"),
                iterations: 100000,
                hash: "SHA-256",
            },
            keyMaterial,
            { name: "AES-CBC", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );
    };

    return (
    <div className="body">
      <main className="main">
          <div className={"row"} style={{
              display:"flex",flexDirection:"row",
              justifyContent:"space-between",
              alignItems:"center"
          }}>
              <div style={{flex:1}}>
                  <input style={{width:"100%"}} type="text" value={url} onChange={(e)=>{
                      setUrl(e.target.value)
                      localStorage.setItem("url",e.target.value)
                  }} placeholder={"Enter url"}/>
              </div>
              <div  style={{width:"100px",display:"flex",alignItems:"center", justifyContent:"flex-end"}}  >
                  <button style={{cursor:"pointer"}}
                          className="px-6 py-2 bg-blue-500 text-white font-semibold rounded-lg shadow-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-400"
                          onClick={async ()=>{
                              if(!url.startsWith("http")){
                                  alert("Url 不合法")
                                  return;
                              }
                              try {
                                  const data = await fetch(url)
                                  const text = await data.text()
                                  setEncryptData(text)
                              }catch (e){
                                  alert("获取失败")
                              }
                          }}>获取</button>
              </div>
          </div>

          <div className={"row"}>
               <textarea rows={2}  style={{width:"100%"}}  onChange={(e)=>{
                   setEncryptData(e.target.value)

               }} value={encryptData} placeholder={"Enter Encrypt Text"} name="encryptData"></textarea>
          </div>


          <div className={"row"} style={{
              display:"flex",flexDirection:"row",
              justifyContent:"space-between",
              alignItems:"center"
          }}>
              <div style={{flex:1}}>
                  <input style={{width:"100%"}} type="text" value={password} onChange={(e)=>{
                      setPassword(e.target.value)
                      localStorage.setItem("password",e.target.value)
                  }} placeholder={"Enter password"}/>
              </div>
              <div  style={{width:"200px",display:"flex",alignItems:"center", justifyContent:"center"}}  >
                  <button style={{cursor:"pointer"}}
                          className="px-6 py-2 bg-blue-500 text-white font-semibold rounded-lg shadow-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-400"
                          onClick={async ()=>{
                              if(!confirm("确定解密？")) {
                                  return;
                              }
                              if(password === ""){
                                  alert("密码不能为空！")
                                  return;
                              }

                              if(encryptData === ""){
                                  alert("解密内容不能为空！")
                                  return;
                              }
                              try {
                                  const decryptedText = await aesDecrypt(password, encryptData);
                                  setPlainData(decryptedText);
                              } catch (err) {
                                  alert("解密失败！");
                              }
                          }}>解密</button>
                  <button style={{cursor:"pointer",marginLeft:12}}
                          className="px-6 py-2 bg-green-500 text-white font-semibold rounded-lg shadow-md hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-blue-400"
                          onClick={async ()=>{
                              try {
                                  if(plainData === ""){
                                      alert("加密密内容不能为空！")
                                      return;
                                  }
                                  if(password === ""){
                                      alert("密码不能为空！")
                                      return;
                                  }
                                  const encryptedText = await aesEncrypt(password, plainData);
                                  await navigator.clipboard.writeText(encryptedText);
                                  alert("加密成功！");
                              } catch (err) {
                                  alert("加密失败！");
                              }
                          }}>加密</button>
              </div>
          </div>

          <div className={"row"}>
              <textarea rows={15} style={{width:"100%"}}  onChange={(e)=>{
                  setPlainData(e.target.value)
              }} value={plainData} placeholder={"Enter Plain Text"} name="plainData"></textarea>
          </div>

      </main>
    </div>
    );
}
