let current=null, timer=null;

// Decode base32 secrets
function base32ToBytes(base32){
  const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  // Strip spaces/padding/lowercase 
  const cleaned=base32.toUpperCase().replace(/[^A-Z2-7]/g,'');

  let bits='';

  // Convert each base32 char into 5-bit binary
  for(const ch of cleaned){
    const val=alphabet.indexOf(ch);
    if(val<0) continue;
    bits += val.toString(2).padStart(5,'0');
  }

  // Rebuild into raw bytes
  const bytes=[];
  for(let i=0;i+8<=bits.length;i+=8){
    bytes.push(parseInt(bits.slice(i,i+8),2));
  }

  return new Uint8Array(bytes);
}

// Accept either raw secrets or full otpauth:// URIs
function parseInput(text){
  text=text.trim();

  if(text.startsWith('otpauth://')){
    const u=new URL(text);
    const p=u.searchParams;

    const secret=p.get('secret')||'';
    const issuer=p.get('issuer')||'';

// Parse account name from otpauth label
    const label=decodeURIComponent((u.pathname||'').replace(/^\/+/, ''));

    const account=label.includes(':')
      ? label.split(':').slice(1).join(':')
      : label;

    return {
      secret,
      issuer,
      account,
      algo:(p.get('algorithm')||'SHA1').toUpperCase(),
      digits:parseInt(p.get('digits')||'6',10),
      period:parseInt(p.get('period')||'30',10)
    };
  }

  // Raw base32 secret fallback
  return {
    secret:text,
    issuer:'',
    account:'',
    algo:'SHA1',
    digits:6,
    period:30
  };
}

// RFC4226 HOTP implementation using Web Crypto HMAC
async function hotp(secretBytes, counter, algo='SHA-1', digits=6){
  const buf=new ArrayBuffer(8);
  const view=new DataView(buf);

  // HOTP counter must be encoded as 8-byte big-endian
  view.setUint32(4, counter >>> 0);
  view.setUint32(0, Math.floor(counter / 0x100000000) >>> 0);

  const key=await crypto.subtle.importKey(
    'raw',
    secretBytes,
    {name:'HMAC', hash:{name:algo}},
    false,
    ['sign']
  );

  const sig=new Uint8Array(
    await crypto.subtle.sign('HMAC', key, buf)
  );

  // Dynamic truncation step from RFC4226
  const offset=sig[sig.length-1] & 0x0f;

  const bin=
    ((sig[offset] & 0x7f) << 24) |
    ((sig[offset+1] & 0xff) << 16) |
    ((sig[offset+2] & 0xff) << 8) |
    (sig[offset+3] & 0xff);

  return (bin % (10 ** digits))
    .toString()
    .padStart(digits, '0');
}



async function update(){
  if(!current) return;
  const epoch=Math.floor(Date.now()/1000);

  // TOTP = HOTP(counter = current time window)
  const counter=Math.floor(epoch/current.period);
  const remaining=current.period - (epoch % current.period);
  document.getElementById('token').textContent = await hotp(current.secretBytes, counter, current.algo, current.digits);
  document.getElementById('countdown').textContent = remaining;
}



async function initializeToken(){
  const raw=document.getElementById('input').value;
  const parsed=parseInput(raw);
  const secretBytes=base32ToBytes(parsed.secret);

  if(!secretBytes.length){
    document.getElementById('status').textContent='Invalid secret key. Paste Base32 or otpauth:// URI';
    return;
  }


  current={...parsed, secretBytes, algo: parsed.algo.replace('SHA1','SHA-1')};
  document.getElementById('issuer').textContent=current.issuer || '-';
  document.getElementById('account').textContent=current.account || '-';
  document.getElementById('status').textContent='Successful! Your token was generated locally.';

  await update();
  if(timer) clearInterval(timer);

  // Refresh countdown/token continuously
  timer=setInterval(update, 250);
}



document.getElementById('generate_otp').addEventListener('click', initializeToken);
document.getElementById('copy').addEventListener('click', async ()=>{

  const t=document.getElementById('token').textContent;
  if(t && t !== '------') await navigator.clipboard.writeText(t);

});


document.getElementById('input').addEventListener('keydown', e=>{
  if(e.key==='Enter' && (e.ctrlKey || e.metaKey)) initializeToken();
});



// Toggle theme
const themeToggle=document.getElementById('theme_toggle');

const moonIcon=document.getElementById('moon_icon');
const sunIcon=document.getElementById('sun_icon');

function applyTheme(theme){

  document.body.classList.toggle(
    'dark',
    theme==='dark'
  );

  moonIcon.style.display =
    theme==='dark'
      ? 'none'
      : 'block';

  sunIcon.style.display =
    theme==='dark'
      ? 'block'
      : 'none';

  localStorage.setItem('theme', theme);
}

const savedTheme=localStorage.getItem('theme');

if(savedTheme){
  applyTheme(savedTheme);
}else{
  const prefersDark=window.matchMedia(
    '(prefers-color-scheme: dark)'
  ).matches;

  applyTheme(prefersDark ? 'dark' : 'light');
}

themeToggle.addEventListener('click', ()=>{

  const isDark=document.body.classList.contains('dark');

  applyTheme(
    isDark ? 'light' : 'dark'
  );
});