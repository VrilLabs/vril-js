'use client';

import { useState, useEffect, useRef, useCallback, type ReactNode } from 'react';

export interface CommandItem {
  id: string; title: string; group: string;
  icon?: ReactNode; keywords?: string[]; action: () => void;
}

export function CommandPalette({ commands, open, onClose }: { commands: CommandItem[]; open: boolean; onClose: () => void }) {
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(-1);
  const inputRef = useRef<HTMLInputElement>(null);

  const filtered = commands.filter(cmd => {
    if (!query.trim()) return true;
    const q = query.toLowerCase();
    return cmd.title.toLowerCase().includes(q) || cmd.keywords?.some(k => k.toLowerCase().includes(q));
  });

  const groups: Record<string, CommandItem[]> = {};
  const groupOrder: string[] = [];
  filtered.forEach(cmd => {
    if (!groups[cmd.group]) { groups[cmd.group] = []; groupOrder.push(cmd.group); }
    groups[cmd.group].push(cmd);
  });

  useEffect(() => {
    if (open) { setQuery(''); setSelectedIndex(-1); setTimeout(() => inputRef.current?.focus(), 50); }
  }, [open]);

  const handleKey = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setSelectedIndex(p => p < filtered.length - 1 ? p + 1 : 0); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setSelectedIndex(p => p > 0 ? p - 1 : filtered.length - 1); }
    else if (e.key === 'Enter' && selectedIndex >= 0 && filtered[selectedIndex]) { e.preventDefault(); filtered[selectedIndex].action(); onClose(); }
    else if (e.key === 'Escape') onClose();
  }, [filtered, selectedIndex, onClose]);

  if (!open) return null;

  let idx = 0;
  return (
    <div className="fixed inset-0 z-[500] flex items-start justify-center pt-[20vh]" onClick={onClose}>
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />
      <div className="relative z-10 w-[min(560px,calc(100vw-2rem))] bg-[#0d1017] border border-white/10 rounded-2xl shadow-2xl overflow-hidden" onClick={e => e.stopPropagation()}>
        <div className="flex items-center gap-3 px-4 py-3 border-b border-white/8 bg-[#111520]">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#9b5eff" strokeWidth="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>
          <input ref={inputRef} type="text" value={query} onChange={e => { setQuery(e.target.value); setSelectedIndex(-1); }} onKeyDown={handleKey} placeholder="Type a command..." className="flex-1 bg-transparent text-white font-mono text-sm outline-none placeholder:text-white/30" />
          <kbd className="px-1.5 py-0.5 text-[9px] font-mono bg-white/5 border border-white/10 rounded text-white/30">ESC</kbd>
        </div>
        <div className="max-h-72 overflow-y-auto py-2">
          {groupOrder.map(group => (
            <div key={group}>
              <div className="px-4 py-1.5 font-mono text-[10px] tracking-[0.14em] uppercase text-white/20">{group}</div>
              {groups[group].map(cmd => {
                const i = idx++;
                return (
                  <button key={cmd.id} onClick={() => { cmd.action(); onClose(); }} onMouseEnter={() => setSelectedIndex(i)}
                    className={`w-full flex items-center gap-3 px-4 py-2 text-left transition-colors ${i === selectedIndex ? 'bg-[#9b5eff]/12 text-white' : 'text-white/50 hover:text-white/70'}`}>
                    <span className="flex-shrink-0 opacity-60 w-4 h-4">{cmd.icon || <span className="w-3 h-3 rounded-full bg-white/10 block" />}</span>
                    <span className="font-mono text-sm">{cmd.title}</span>
                  </button>
                );
              })}
            </div>
          ))}
          {filtered.length === 0 && <div className="px-4 py-8 text-center font-mono text-sm text-white/20">No commands found</div>}
        </div>
        <div className="flex items-center justify-between px-4 py-2 border-t border-white/8 bg-[#111520]">
          <span className="font-mono text-[10px] text-white/20">{filtered.length} command{filtered.length !== 1 ? 's' : ''}</span>
          <div className="flex gap-2 text-[9px] font-mono text-white/20"><span>↑↓ navigate</span><span>↵ select</span><span>esc close</span></div>
        </div>
      </div>
    </div>
  );
}
