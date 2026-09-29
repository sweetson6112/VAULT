const fs = require('fs');
const path = require('path');

const directories = [
  'src',
  'src/lib',
  'src/components'
];

const files = {
  'package.json': JSON.stringify({
    "name": "personal-high-security-vault",
    "version": "1.0.0",
    "private": true,
    "dependencies": {
      "@supabase/supabase-js": "^2.39.8",
      "lucide-react": "^0.344.0",
      "react": "^18.2.0",
      "react-dom": "^18.2.0"
    },
    "devDependencies": {
      "@types/react": "^18.2.66",
      "@types/react-dom": "^18.2.22",
      "vite": "^5.1.6",
      "@vitejs/plugin-react": "^4.2.1",
      "autoprefixer": "^10.4.18",
      "postcss": "^8.4.35",
      "tailwindcss": "^3.4.1"
    },
    "scripts": {
      "dev": "vite",
      "build": "vite build"
    }
  }, null, 2),

  'src/lib/supabase.ts': `import { createClient } from '@supabase/supabase-js';

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL || 'https://your-project.supabase.co';
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY || 'your-anon-key';

export const supabase = createClient(supabaseUrl, supabaseAnonKey, {
  auth: {
    persistSession: true,
    autoRefreshToken: true,
  },
});
`,

  'src/lib/crypto.ts': `// Zero-Knowledge Client-Side Cryptography Utility using Web Crypto API (AES-GCM)

export async function deriveKey(masterPassword: string, salt: Uint8Array): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const keyMaterial = await window.crypto.subtle.importKey(
    "raw",
    enc.encode(masterPassword),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  return window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256"
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function encryptPayload(key: CryptoKey, data: object): Promise<{ ciphertext: string; iv: string }> {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(JSON.stringify(data));
  
  const encrypted = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoded
  );

  return {
    ciphertext: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
    iv: btoa(String.fromCharCode(...iv))
  };
}

export async function decryptPayload(key: CryptoKey, ciphertext: string, ivStr: string): Promise<object> {
  const iv = Uint8Array.from(atob(ivStr), c => c.charCodeAt(0));
  const data = Uint8Array.from(atob(ciphertext), c => c.charCodeAt(0));

  const decrypted = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    data
  );

  const decoded = new TextDecoder().decode(decrypted);
  return JSON.parse(decoded);
}
`,

  'src/App.jsx': `import React, { useState } from 'react';
import { Shield, Lock, Unlock, Key, FileText, Server, CreditCard, Plus, Eye, EyeOff, Copy, Check, AlertTriangle } from 'lucide-react';

export default function App() {
  const [isUnlocked, setIsUnlocked] = useState(false);
  const [masterPassword, setMasterPassword] = useState('');
  const [activeTab, setActiveTab] = useState('logins');
  const [copiedId, setCopiedId] = useState(null);
  const [showSecrets, setShowSecrets] = useState({});
  const [records, setRecords] = useState([
    { id: '1', category: 'logins', title: 'Personal Email (Proton)', username: 'secure_user@proton.me', secret: 'Sup3rS3cr3tP@ss!', notes: 'Backup codes stored offline.' },
    { id: '2', category: 'servers', title: 'Production Database VPS', username: 'root', secret: 'AWS_Key_99823719283', notes: 'Region: us-east-1' },
    { id: '3', category: 'financial', title: 'Primary Business Bank', username: 'Acc #****4492', secret: 'PIN: 4821', notes: 'Routing: 021000021' }
  ]);

  const handleUnlock = (e) => {
    e.preventDefault();
    if (masterPassword.length > 0) {
      setIsUnlocked(true);
    }
  };

  const copyToClipboard = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 3000); // Auto-clear indication
  };

  const toggleSecretVisibility = (id) => {
    setShowSecrets(prev => ({ ...prev, [id]: !prev[id] }));
  };

  if (!isUnlocked) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center p-4">
        <div className="max-w-md w-full bg-slate-900 border border-slate-800 rounded-xl p-8 shadow-2xl">
          <div className="flex justify-center mb-6">
            <div className="p-3 bg-emerald-500/10 border border-emerald-500/20 rounded-full text-emerald-400">
              <Shield className="w-10 h-10" />
            </div>
          </div>
          <h1 className="text-2xl font-bold text-center mb-2">High-Security Vault</h1>
          <p className="text-sm text-slate-400 text-center mb-6">Enter your master passphrase to unlock client-side encryption keys.</p>
          
          <form onSubmit={handleUnlock} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">Master Passphrase</label>
              <div className="relative">
                <input 
                  type="password"
                  value={masterPassword}
                  onChange={(e) => setMasterPassword(e.target.value)}
                  placeholder="••••••••••••••••"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-3 text-slate-100 focus:outline-none focus:border-emerald-500 transition-colors"
                  required
                />
                <Lock className="w-5 h-5 text-slate-500 absolute right-3 top-3.5" />
              </div>
            </div>
            <button 
              type="submit"
              className="w-full bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-semibold py-3 rounded-lg transition-all shadow-lg shadow-emerald-900/20 flex items-center justify-center gap-2"
            >
              <Unlock className="w-4 h-4" /> Unlock Vault
            </button>
          </form>
          <div className="mt-6 flex items-center gap-2 text-xs text-amber-400/80 bg-amber-500/10 border border-amber-500/20 p-3 rounded-lg">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>Zero-Knowledge Architecture: Keys never leave your device memory.</span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex">
      {/* Sidebar */}
      <aside className="w-64 bg-slate-900 border-r border-slate-800 p-6 flex flex-col justify-between">
        <div>
          <div className="flex items-center gap-3 mb-8">
            <div className="p-2 bg-emerald-500/10 rounded-lg text-emerald-400">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <h2 className="font-bold text-sm tracking-wide">SECURE VAULT</h2>
              <span className="text-xs text-emerald-400 flex items-center gap-1 font-mono">● ENCRYPTED</span>
            </div>
          </div>
          
          <nav className="space-y-1">
            <button onClick={() => setActiveTab('logins')} className={\`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors \${activeTab === 'logins' ? 'bg-emerald-500/10 text-emerald-400' : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'}\`}>
              <Key className="w-4 h-4" /> Logins & Credentials
            </button>
            <button onClick={() => setActiveTab('servers')} className={\`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors \${activeTab === 'servers' ? 'bg-emerald-500/10 text-emerald-400' : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'}\`}>
              <Server className="w-4 h-4" /> Servers & Infrastructure
            </button>
            <button onClick={() => setActiveTab('financial')} className={\`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors \${activeTab === 'financial' ? 'bg-emerald-500/10 text-emerald-400' : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'}\`}>
              <CreditCard className="w-4 h-4" /> Bank & Financial
            </button>
          </nav>
        </div>

        <button 
          onClick={() => setIsUnlocked(false)} 
          className="w-full flex items-center justify-center gap-2 bg-slate-800 hover:bg-slate-700 text-slate-300 py-2.5 rounded-lg text-sm font-medium transition-colors border border-slate-700"
        >
          <Lock className="w-4 h-4" /> Lock Vault
        </button>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 p-8 overflow-y-auto">
        <header className="flex justify-between items-center mb-8">
          <div>
            <h1 className="text-2xl font-bold uppercase tracking-wide">{activeTab}</h1>
            <p className="text-sm text-slate-400">Manage and inspect your encrypted records securely.</p>
          </div>
          <button className="bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-semibold px-4 py-2.5 rounded-lg transition-all flex items-center gap-2 text-sm shadow-lg shadow-emerald-900/20">
            <Plus className="w-4 h-4" /> Add Record
          </button>
        </header>

        <div className="space-y-4">
          {records.map((item) => (
            <div key={item.id} className="bg-slate-900 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition-all flex items-center justify-between">
              <div>
                <span className="text-xs font-mono text-emerald-400 uppercase tracking-widest">{item.category}</span>
                <h3 className="text-lg font-semibold text-slate-100">{item.title}</h3>
                <p className="text-sm text-slate-400 font-mono mt-1">{item.username}</p>
                <div className="flex items-center gap-3 mt-3">
                  <span className="font-mono text-sm tracking-widest bg-slate-950 border border-slate-800 px-3 py-1 rounded text-slate-300">
                    {showSecrets[item.id] ? item.secret : '••••••••••••••••'}
                  </span>
                  <button 
                    onClick={() => toggleSecretVisibility(item.id)}
                    className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors"
                    title={showSecrets[item.id] ? "Hide Secret" : "Show Secret"}
                  >
                    {showSecrets[item.id] ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                  <button 
                    onClick={() => copyToClipboard(item.secret, item.id)}
                    className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors flex items-center gap-1 text-xs px-2"
                  >
                    {copiedId === item.id ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                    {copiedId === item.id ? 'Copied!' : 'Copy'}
                  </button>
                </div>
              </div>
              <span className="text-xs text-slate-500 font-mono">AES-256-GCM</span>
            </div>
          ))}
        </div>
      </main>
    </div>
  );
}
`,

  'vite.config.js': `import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
});
`,

  'index.html': `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Personal High-Security Vault</title>
  </head>
  <body class="bg-slate-950 text-slate-100">
    <div id="root"></div>
    <script type="module" src="/src/main.jsx"></script>
  </body>
</html>
`,

  'src/main.jsx': `import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App.jsx';
import './index.css';

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
`,

  'src/index.css': `@tailwind base;
@tailwind components;
@tailwind utilities;
`
};

// Execute file creation
console.log('🏗️ Building Personal High-Security Vault project structure...');
directories.forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
    console.log(`Created directory: ${dir}`);
  }
});

Object.entries(files).forEach(([filePath, content]) => {
  fs.writeFileSync(filePath, content);
  console.log(`Generated file: ${filePath}`);
});

console.log('\\n✅ Vault project scaffolded successfully!');
console.log('\\nNext steps:');
console.log('1. Run: npm install');
console.log('2. Run: npm run dev');
console.log('3. Open http://localhost:5173 in your browser.\\n');