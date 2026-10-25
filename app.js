(() => {
 const iterations=210000;
 const encoder=new TextEncoder();
 const defaultAvatar='data:image/svg+xml,%3Csvg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 96 96"%3E%3Crect width="96" height="96" rx="48" fill="%23e2e8f0"/%3E%3Ccircle cx="48" cy="36" r="17" fill="%2364758b"/%3E%3Cpath d="M16 88c2-19 14-29 32-29s30 10 32 29" fill="%2364758b"/%3E%3C/svg%3E';
 const normalizeEmail=value=>String(value||'').trim().toLowerCase();
 const normalizePhone=value=>String(value||'').replace(/\D/g,'');
 const normalizeIdentifier=value=>{
  const identifier=String(value||'').trim();
  return identifier.includes('@')?normalizeEmail(identifier):normalizePhone(identifier);
 };
 const bytesToBase64=bytes=>btoa(String.fromCharCode(...new Uint8Array(bytes)));
 const base64ToBytes=value=>Uint8Array.from(atob(value),char=>char.charCodeAt(0));
 async function createCredential(password){
  if(!globalThis.crypto?.subtle||!globalThis.crypto?.getRandomValues)throw new Error('La protection du mot de passe nécessite une connexion sécurisée.');
  const salt=crypto.getRandomValues(new Uint8Array(16));
  const key=await crypto.subtle.importKey('raw',encoder.encode(password),'PBKDF2',false,['deriveBits']);
  const bits=await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt,iterations},key,256);
  return {passwordSalt:bytesToBase64(salt),passwordHash:bytesToBase64(bits),passwordIterations:iterations};
 }
 async function verifyCredential(user,password){
  if(user.passwordSalt&&user.passwordHash){
   if(!globalThis.crypto?.subtle)throw new Error('La connexion nécessite une connexion sécurisée.');
   const key=await crypto.subtle.importKey('raw',encoder.encode(password),'PBKDF2',false,['deriveBits']);
   const count=Number.isInteger(user.passwordIterations)&&user.passwordIterations>=100000&&user.passwordIterations<=1000000?user.passwordIterations:iterations;
   const bits=await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:base64ToBytes(user.passwordSalt),iterations:count},key,256);
   return bytesToBase64(bits)===user.passwordHash;
  }
  return typeof user.pw==='string'&&user.pw===password;
 }
 const avatarUrl=value=>{
  if(!value)return defaultAvatar;
  try{const url=new URL(value);return url.protocol==='https:'?url.href:defaultAvatar}catch{return defaultAvatar}
 };
 const isValidAvatarUrl=value=>{
  if(!value)return true;
  try{return new URL(value).protocol==='https:'}catch{return false}
 };
 globalThis.KitimaAuth=Object.freeze({DEFAULT_AVATAR:defaultAvatar,normalizeEmail,normalizePhone,normalizeIdentifier,createCredential,verifyCredential,avatarUrl,isValidAvatarUrl});
})();
