// Password Strength & HIBP leak check (client-side)
const pwd = document.getElementById('password');
const entropyEl = document.getElementById('entropy');
const strengthEl = document.getElementById('strength');
const leakEl = document.getElementById('leak');
const toggleBtn = document.getElementById('toggle-visibility');
const checkLeakBtn = document.getElementById('check-leak');
const enableHibp = document.getElementById('enable-hibp');

function estimateEntropy(password) {
  if (!password) return 0;
  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (/[^A-Za-z0-9]/.test(password)) pool += 32; // rough symbol count
  const entropy = Math.log2(Math.pow(pool, password.length));
  return Math.round(entropy);
}

function strengthLabel(entropy) {
  if (entropy < 28) return 'Very weak';
  if (entropy < 36) return 'Weak';
  if (entropy < 60) return 'Reasonable';
  if (entropy < 128) return 'Strong';
  return 'Very strong';
}

pwd.addEventListener('input', () => {
  const e = estimateEntropy(pwd.value);
  entropyEl.textContent = e;
  strengthEl.textContent = strengthLabel(e);
  leakEl.textContent = '—';
});

toggleBtn.addEventListener('click', () => {
  if (pwd.type === 'password') { pwd.type = 'text'; toggleBtn.textContent = 'Hide'; }
  else { pwd.type = 'password'; toggleBtn.textContent = 'Show'; }
});

// HIBP k-anonymity check (client-side)
// Note: CORS may block direct calls in some browsers; this is a best-effort demo.
async function sha1Hex(str) {
  const buf = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest('SHA-1', buf);
  const hex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2,'0')).join('').toUpperCase();
  return hex;
}

async function checkPwned(password) {
  if (!password) return 'No password';
  try {
    const sha1 = await sha1Hex(password);
    const prefix = sha1.slice(0,5);
    const suffix = sha1.slice(5);
    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
    if (!res.ok) return 'HIBP unavailable';
    const text = await res.text();
    const lines = text.split('\n');
    for (const line of lines) {
      const [hashSuffix, count] = line.trim().split(':');
      if (hashSuffix === suffix) {
        return `Pwned ${count} times`;
      }
    }
    return 'Not found';
  } catch (e) {
    return 'Error checking HIBP';
  }
}

checkLeakBtn.addEventListener('click', async () => {
  if (!enableHibp.checked) {
    leakEl.textContent = 'HIBP disabled';
    return;
  }
  leakEl.textContent = 'Checking…';
  const result = await checkPwned(pwd.value);
  leakEl.textContent = result;
});
    
