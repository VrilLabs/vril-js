'use client';

import { useState, useCallback, useEffect, createContext, useContext, type ReactNode } from 'react';

interface CrystalWindowContextType {
  open: (id: string) => void;
  close: () => void;
  isOpen: boolean;
  isClosing: boolean;
  activePanel: string | null;
}

const CrystalWindowContext = createContext<CrystalWindowContextType>({
  open: () => {}, close: () => {}, isOpen: false, isClosing: false, activePanel: null,
});

export function useCrystalWindow() { return useContext(CrystalWindowContext); }

export function CrystalWindowProvider({ children }: { children: ReactNode }) {
  const [isOpen, setIsOpen] = useState(false);
  const [activePanel, setActivePanel] = useState<string | null>(null);
  const [isClosing, setIsClosing] = useState(false);

  const open = useCallback((id: string) => {
    setActivePanel(id); setIsOpen(true); setIsClosing(false);
  }, []);

  const close = useCallback(() => {
    setIsClosing(true);
    setTimeout(() => { setIsOpen(false); setIsClosing(false); setActivePanel(null); }, 400);
  }, []);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape' && isOpen) { e.preventDefault(); close(); } };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [isOpen, close]);

  return (
    <CrystalWindowContext.Provider value={{ open, close, isOpen, isClosing, activePanel }}>
      {children}
    </CrystalWindowContext.Provider>
  );
}

interface PanelConfig {
  id: string;
  title: string;
  badge?: string;
  children: ReactNode;
}

export function CrystalWindow({ panels }: { panels: PanelConfig[] }) {
  const { isOpen, isClosing, activePanel, close } = useCrystalWindow();
  const panel = panels.find(p => p.id === activePanel);

  return (
    <>
      <div
        className={`fixed inset-0 z-[295] transition-all duration-500 ${isOpen ? 'bg-black/55 backdrop-blur-sm pointer-events-auto' : 'bg-transparent pointer-events-none'}`}
        onClick={close}
      />
      <div
        className={`fixed top-16 left-0 right-0 z-[300] max-h-[calc(100dvh-4rem-2rem)] flex flex-col rounded-b-3xl overflow-hidden transition-all duration-500 ${
          isOpen && !isClosing ? 'translate-y-0 opacity-100 pointer-events-auto' : '-translate-y-full opacity-0 pointer-events-none'
        }`}
        style={{ background: 'rgba(8,10,18,0.85)', backdropFilter: 'blur(32px) saturate(200%)', border: '1px solid rgba(255,255,255,0.08)', borderTop: 'none', boxShadow: '0 24px 80px rgba(0,0,0,0.7), 0 8px 32px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.06)' }}
      >
        <div className="h-px w-full" style={{ background: 'linear-gradient(90deg, transparent, rgba(0,255,200,0.18) 20%, rgba(0,255,200,0.18) 80%, transparent)' }} />
        <div className="flex items-center justify-center py-3 cursor-grab" onClick={close}>
          <div className="w-12 h-1 rounded-full bg-gradient-to-r from-[#00FFC8] to-[#0A84FF] opacity-50" />
        </div>
        {panel && (
          <div className="flex-1 overflow-y-auto px-8 pb-8">
            <div className="flex items-center justify-between pb-5 mb-6 border-b border-white/8">
              <div className="flex items-center gap-4">
                {panel.badge && (
                  <span className="font-mono text-[9px] tracking-[0.14em] uppercase px-2.5 py-0.5 rounded-full border border-[#00FFC8]/35 text-[#00FFC8] bg-[#00FFC8]/7 flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#00FFC8] animate-pulse" />{panel.badge}
                  </span>
                )}
                <h3 className="text-xl font-extrabold tracking-tight text-white">{panel.title}</h3>
              </div>
              <button onClick={close} className="w-9 h-9 rounded-full flex items-center justify-center text-white/40 bg-white/4 border border-white/8 hover:text-white hover:rotate-90 transition-all" aria-label="Close">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M18 6L6 18M6 6l12 12"/></svg>
              </button>
            </div>
            {panel.children}
          </div>
        )}
      </div>
    </>
  );
}
