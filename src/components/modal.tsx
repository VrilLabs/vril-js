'use client';

import { useState, useCallback, type ReactNode } from 'react';

type ModalVariant = 'info' | 'confirm' | 'destructive';

export function VrilModal() {
  const [state, setState] = useState<{
    open: boolean; variant: ModalVariant; title: string; subtitle?: string;
    body: ReactNode; resolve?: (v: boolean) => void;
  }>({ open: false, variant: 'info', title: '', body: null });

  const info = useCallback((opts: { title: string; subtitle?: string; body: ReactNode }) => setState({ open: true, variant: 'info', ...opts }), []);
  const confirm = useCallback((opts: { title: string; subtitle?: string; body: ReactNode }): Promise<boolean> =>
    new Promise(resolve => setState({ open: true, variant: 'confirm', ...opts, resolve })), []);
  const destructive = useCallback((opts: { title: string; subtitle?: string; body: ReactNode }): Promise<boolean> =>
    new Promise(resolve => setState({ open: true, variant: 'destructive', ...opts, resolve })), []);
  const close = useCallback((value: boolean) => { state.resolve?.(value); setState(p => ({ ...p, open: false })); }, [state]);

  if (!state.open) return null;
  const colors = { info: 'text-[#00FFC8] bg-[#00FFC8]/12 border-[#00FFC8]/30', confirm: 'text-[#f5a623] bg-[#f5a623]/12 border-[#f5a623]/30', destructive: 'text-[#ff4d6a] bg-[#ff4d6a]/12 border-[#ff4d6a]/30' };
  const labels = { info: 'Information', confirm: 'Confirmation', destructive: 'Destructive' };

  return (
    <div className="fixed inset-0 z-[400] flex items-center justify-center" onClick={() => close(false)}>
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />
      <div className="relative z-10 w-[min(560px,calc(100vw-2rem))] bg-[#0d1017] border border-white/10 rounded-3xl overflow-hidden shadow-2xl animate-in fade-in zoom-in-95 duration-200" onClick={e => e.stopPropagation()}>
        <div className="flex items-start justify-between p-5 border-b border-white/8 bg-[#111520]">
          <div className="flex flex-col gap-2">
            <span className={`font-mono text-[9px] tracking-[0.14em] uppercase px-2.5 py-0.5 rounded-full border flex items-center gap-1.5 w-fit ${colors[state.variant]}`}>
              <span className="w-1.5 h-1.5 rounded-full bg-current" />{labels[state.variant]}
            </span>
            <h3 className="font-bold text-lg text-white">{state.title}</h3>
            {state.subtitle && <p className="text-sm text-white/50">{state.subtitle}</p>}
          </div>
          <button onClick={() => close(false)} className="w-8 h-8 rounded-full flex items-center justify-center text-white/40 bg-white/4 border border-white/8 hover:text-white hover:rotate-90 transition-all" aria-label="Close">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M18 6L6 18M6 6l12 12"/></svg>
          </button>
        </div>
        <div className="p-6 max-h-[50dvh] overflow-y-auto text-white/70 text-sm leading-relaxed">{state.body}</div>
        <div className="flex items-center justify-end gap-2 px-6 py-4 border-t border-white/8 bg-[#111520]">
          {state.variant !== 'info' && (
            <button onClick={() => close(false)} className="px-4 py-2 bg-transparent text-white/70 font-semibold text-sm rounded-lg border border-white/10 hover:border-[#00FFC8] hover:text-[#00FFC8] transition-all">Cancel</button>
          )}
          <button onClick={() => close(true)} className={`px-4 py-2 font-semibold text-sm rounded-lg border transition-all ${
            state.variant === 'destructive' ? 'bg-[#ff4d6a] text-white border-[#ff4d6a]' :
            state.variant === 'confirm' ? 'bg-[#f5a623] text-[#080a0e] border-[#f5a623]' : 'bg-[#00FFC8] text-[#080a0e] border-[#00FFC8]'
          }`}>{state.variant === 'destructive' ? 'Destroy' : state.variant === 'confirm' ? 'Confirm' : 'OK'}</button>
        </div>
      </div>
    </div>
  );
}
