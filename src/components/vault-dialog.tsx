'use client';

import { useState } from 'react';
import { VrilVault, type EncryptionResult } from '@/lib/vril/security/crypto/vault';

const vault = new VrilVault();

export function VaultDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [passphrase, setPassphrase] = useState('');
  const [plaintext, setPlaintext] = useState('');
  const [status, setStatus] = useState<'idle' | 'encrypting' | 'decrypting' | 'done' | 'error'>('idle');
  const [result, setResult] = useState('');
  const [resultLabel, setResultLabel] = useState('');
  const [kdfProgress, setKdfProgress] = useState(0);
  const [strength, setStrength] = useState({ score: 0, max: 6, label: '' });

  const handlePass = (v: string) => { setPassphrase(v); setStrength(vault.assessStrength(v)); };

  const handleEncrypt = async () => {
    if (!passphrase || !plaintext) return;
    setStatus('encrypting'); setKdfProgress(0);
    const iv = setInterval(() => setKdfProgress(p => Math.min(p + Math.random() * 15, 90)), 80);
    try {
      const enc = await vault.encrypt(passphrase, plaintext);
      clearInterval(iv); setKdfProgress(100);
      setResult(JSON.stringify(enc, null, 2)); setResultLabel('Ciphertext Bundle'); setStatus('done');
    } catch (e) { clearInterval(iv); setResult(e instanceof Error ? e.message : 'Failed'); setResultLabel('Error'); setStatus('error'); }
  };

  const handleDecrypt = async () => {
    if (!passphrase || !plaintext) return;
    setStatus('decrypting'); setKdfProgress(0);
    const iv = setInterval(() => setKdfProgress(p => Math.min(p + Math.random() * 15, 90)), 80);
    try {
      const bundle = JSON.parse(plaintext) as EncryptionResult;
      const dec = await vault.decrypt(passphrase, bundle);
      clearInterval(iv); setKdfProgress(100);
      setResult(dec.plaintext); setResultLabel('Plaintext'); setStatus('done');
    } catch { clearInterval(iv); setResult('Wrong passphrase or corrupted bundle'); setResultLabel('Error'); setStatus('error'); }
  };

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-[400] flex items-center justify-center" onClick={onClose}>
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />
      <div className="relative z-10 w-[min(560px,calc(100vw-2rem))] max-h-[min(84dvh,700px)] bg-[#0d1017] border border-white/10 rounded-3xl overflow-hidden shadow-2xl" onClick={e => e.stopPropagation()}>
        <div className="flex items-start justify-between p-5 border-b border-white/8 bg-[#111520]">
          <div className="flex flex-col gap-2">
            <span className="font-mono text-[9px] tracking-[0.14em] uppercase px-2.5 py-0.5 rounded-full text-[#f5a623] bg-[#f5a623]/12 border border-[#f5a623]/30 flex items-center gap-1.5 w-fit">
              <span className="w-1.5 h-1.5 rounded-full bg-current" />Vault
            </span>
            <h3 className="font-bold text-lg text-white">OmegaVault</h3>
            <p className="text-sm text-white/50">AES-256-GCM + PBKDF2-SHA-512</p>
          </div>
          <button onClick={onClose} className="w-8 h-8 rounded-full flex items-center justify-center text-white/40 bg-white/4 border border-white/8 hover:text-white hover:rotate-90 transition-all" aria-label="Close">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M18 6L6 18M6 6l12 12"/></svg>
          </button>
        </div>
        <div className="p-6 flex flex-col gap-4 max-h-[50dvh] overflow-y-auto">
          <div className="flex flex-col items-center gap-3 py-2">
            <div className={`w-16 h-16 rounded-full border-2 flex items-center justify-center transition-all ${
              status === 'encrypting' || status === 'decrypting' ? 'border-[#f5a623] text-[#f5a623] animate-pulse' :
              status === 'done' ? 'border-[#4ade80] text-[#4ade80]' :
              status === 'error' ? 'border-[#ff4d6a] text-[#ff4d6a]' : 'border-white/10 text-white/40'
            }`}>
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            </div>
            <span className="font-mono text-xs text-white/30 tracking-widest uppercase">
              {status === 'idle' ? 'Standing by' : status === 'encrypting' ? 'Sealing...' : status === 'decrypting' ? 'Unsealing...' : status === 'done' ? 'Complete' : 'Failed'}
            </span>
          </div>
          {(status === 'encrypting' || status === 'decrypting') && (
            <div className="space-y-1">
              <div className="flex justify-between text-[10px] font-mono text-white/40"><span>Deriving key...</span><span>{Math.round(kdfProgress)}%</span></div>
              <div className="h-1.5 bg-white/5 rounded-full overflow-hidden"><div className="h-full bg-gradient-to-r from-[#f5a623] to-[#0A84FF] rounded-full transition-all" style={{ width: `${kdfProgress}%` }} /></div>
            </div>
          )}
          <div className="space-y-1.5">
            <label className="font-mono text-[10px] tracking-[0.14em] uppercase text-white/30">Passphrase</label>
            <input type="password" value={passphrase} onChange={e => handlePass(e.target.value)} className="w-full px-3 py-2 bg-[#161b28] border border-white/10 rounded-lg text-white font-mono text-sm focus:outline-none focus:border-[#00FFC8]" placeholder="Enter passphrase" />
            <div className="flex gap-1">{Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className={`h-1 flex-1 rounded-full ${i < strength.score ? strength.score <= 2 ? 'bg-[#ff4d6a]' : strength.score <= 4 ? 'bg-[#f5a623]' : 'bg-[#4ade80]' : 'bg-white/5'}`} />
            ))}</div>
          </div>
          <div className="space-y-1.5">
            <label className="font-mono text-[10px] tracking-[0.14em] uppercase text-white/30">Input</label>
            <textarea value={plaintext} onChange={e => setPlaintext(e.target.value)} rows={3} className="w-full px-3 py-2 bg-[#161b28] border border-white/10 rounded-lg text-white font-mono text-sm resize-none focus:outline-none focus:border-[#00FFC8]" placeholder="Enter plaintext or paste a bundle" />
          </div>
          {result && (
            <div className="space-y-1.5">
              <label className="font-mono text-[10px] tracking-[0.14em] uppercase text-white/30">{resultLabel}</label>
              <pre className="px-3 py-2 bg-[#0a0c10] border border-white/10 rounded-lg text-[#00FFC8] font-mono text-xs overflow-x-auto whitespace-pre-wrap max-h-32">{result}</pre>
            </div>
          )}
        </div>
        <div className="flex items-center justify-between gap-3 px-6 py-4 border-t border-white/8 bg-[#111520]">
          <span className="font-mono text-[10px] text-white/20">AES-256-GCM · PBKDF2-SHA-512 · 600K iter</span>
          <div className="flex gap-2">
            <button onClick={handleEncrypt} disabled={!passphrase || !plaintext || status === 'encrypting'} className="px-4 py-2 bg-[#f5a623] text-[#080a0e] font-semibold text-sm rounded-lg border border-[#f5a623] hover:bg-[#c47d0d] transition-all disabled:opacity-40">Seal</button>
            <button onClick={handleDecrypt} disabled={!passphrase || !plaintext || status === 'decrypting'} className="px-4 py-2 bg-transparent text-white/70 font-semibold text-sm rounded-lg border border-white/10 hover:border-[#00FFC8] hover:text-[#00FFC8] transition-all disabled:opacity-40">Unseal</button>
          </div>
        </div>
      </div>
    </div>
  );
}
