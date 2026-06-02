'use client';

import { useState, useEffect, useRef, useCallback, type ReactNode } from 'react';

// ─── Types ────────────────────────────────────────────────────────

export interface CommandItem {
  id: string;
  title: string;
  group: string;
  icon?: ReactNode;
  keywords?: string[];
  action: () => void;
}

export interface DocsEntry {
  path: string;
  method: string;
  summary: string;
  tags?: string[];
  docsAnchor?: string;
  hasSubmenu?: boolean;
}

export interface CommandPaletteConfig {
  /** Configurable site name displayed before the input field. If not set, palette operates in default mode. */
  siteName?: string;
  /** Enable the docs explorer mode (triggered by /, ?, or #). Default: true when siteName is set */
  docsExplorer?: boolean;
  /** OpenAPI endpoint to fetch docs from. Default: /api/openapi */
  openApiEndpoint?: string;
  /** Custom hint text shown when in default mode */
  hint?: string;
}

export interface CommandPaletteProps {
  commands: CommandItem[];
  open: boolean;
  onClose: () => void;
  config?: CommandPaletteConfig;
}

type PaletteMode = 'commands' | 'docs' | 'submenu';

// ─── Component ────────────────────────────────────────────────────

export function CommandPalette({ commands, open, onClose, config }: CommandPaletteProps) {
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(-1);
  const [mode, setMode] = useState<PaletteMode>('commands');
  const [docsEntries, setDocsEntries] = useState<DocsEntry[]>([]);
  const [docsLoading, setDocsLoading] = useState(false);
  const [submenuTag, setSubmenuTag] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const docsFetchedRef = useRef(false);

  const siteName = config?.siteName;
  const docsExplorerEnabled = config?.docsExplorer ?? !!siteName;
  const openApiEndpoint = config?.openApiEndpoint ?? '/api/openapi';
  const hintText = docsExplorerEnabled
    ? (config?.hint ?? 'Type /, ?, or # to explore')
    : 'Type a command...';

  // Fetch OpenAPI docs when entering docs mode
  const fetchDocs = useCallback(async () => {
    if (docsFetchedRef.current) return;
    docsFetchedRef.current = true;
    setDocsLoading(true);
    try {
      const res = await fetch(openApiEndpoint);
      if (res.ok) {
        const spec = await res.json();
        const entries: DocsEntry[] = [];
        if (spec.paths) {
          for (const [path, methods] of Object.entries(spec.paths)) {
            const methodObj = methods as Record<string, { summary?: string; tags?: string[]; 'x-docs-anchor'?: string; 'x-has-submenu'?: boolean }>;
            for (const [method, operation] of Object.entries(methodObj)) {
              if (['get', 'post', 'put', 'patch', 'delete'].includes(method)) {
                entries.push({
                  path,
                  method: method.toUpperCase(),
                  summary: operation.summary ?? `${method.toUpperCase()} ${path}`,
                  tags: operation.tags,
                  docsAnchor: operation['x-docs-anchor'],
                  hasSubmenu: operation['x-has-submenu'],
                });
              }
            }
          }
        }
        setDocsEntries(entries);
      }
    } catch {
      // Silently fail — docs explorer won't show entries
    } finally {
      setDocsLoading(false);
    }
  }, [openApiEndpoint]);

  // Reset on open
  useEffect(() => {
    if (open) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setQuery(''); setSelectedIndex(-1); setMode('commands'); setSubmenuTag(null);
      setTimeout(() => inputRef.current?.focus(), 50);
    } else {
      // Reset fetch state when palette closes
      docsFetchedRef.current = false;
      setDocsEntries([]);
    }
  }, [open]);

  // Reset fetch state when endpoint changes
  useEffect(() => {
    docsFetchedRef.current = false;
    setDocsEntries([]);
  }, [openApiEndpoint]);

  // Switch mode based on trigger characters
  useEffect(() => {
    if (!docsExplorerEnabled) return;
    if (query === '/' || query === '?' || query === '#') {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setMode('docs'); setQuery(''); setSelectedIndex(-1); setSubmenuTag(null);
      fetchDocs();
    }
  }, [query, docsExplorerEnabled, fetchDocs]);

  // Filter logic
  const filtered = mode === 'commands'
    ? commands.filter(cmd => {
        if (!query.trim()) return true;
        const q = query.toLowerCase();
        return cmd.title.toLowerCase().includes(q) || cmd.keywords?.some(k => k.toLowerCase().includes(q));
      })
    : [];

  // In submenu mode, show only entries matching the submenu tag (Security sub-sections)
  const filteredDocs = (mode === 'docs' || mode === 'submenu')
    ? docsEntries.filter(entry => {
        // In submenu mode, filter to Security sub-entries (tags starting with "Security ›")
        if (mode === 'submenu' && submenuTag) {
          const tag = entry.tags?.[0] ?? '';
          if (!tag.startsWith(submenuTag + ' ›') && tag !== submenuTag) return false;
          // Exclude the parent submenu entry itself
          if (entry.hasSubmenu) return false;
        }
        // In docs mode, show top-level entries only (collapse Security sub-items into the parent)
        if (mode === 'docs') {
          const tag = entry.tags?.[0] ?? '';
          // Hide Security sub-entries (those with › in the tag) — they're accessed via submenu
          if (tag.includes('›')) return false;
        }
        if (!query.trim()) return true;
        const q = query.toLowerCase();
        return entry.path.toLowerCase().includes(q) || entry.summary.toLowerCase().includes(q) || entry.method.toLowerCase().includes(q) || entry.tags?.some(t => t.toLowerCase().includes(q));
      })
    : [];

  const totalItems = mode === 'commands' ? filtered.length : filteredDocs.length;

  // Groups for command mode
  const groups: Record<string, CommandItem[]> = {};
  const groupOrder: string[] = [];
  if (mode === 'commands') {
    filtered.forEach(cmd => {
      if (!groups[cmd.group]) { groups[cmd.group] = []; groupOrder.push(cmd.group); }
      groups[cmd.group].push(cmd);
    });
  }

  // Groups for docs mode
  const docsGroups: Record<string, DocsEntry[]> = {};
  const docsGroupOrder: string[] = [];
  if (mode === 'docs' || mode === 'submenu') {
    filteredDocs.forEach(entry => {
      const tag = entry.tags?.[0] ?? 'General';
      // In submenu mode, use the sub-tag label (after ›)
      const groupLabel = mode === 'submenu' && tag.includes('›')
        ? tag.split('›').pop()?.trim() ?? tag
        : tag;
      if (!docsGroups[groupLabel]) { docsGroups[groupLabel] = []; docsGroupOrder.push(groupLabel); }
      docsGroups[groupLabel].push(entry);
    });
  }

  const navigateToEntry = (entry: DocsEntry) => {
    if (entry.hasSubmenu) {
      // Open submenu for this tag
      setMode('submenu');
      setSubmenuTag(entry.tags?.[0] ?? null);
      setQuery('');
      setSelectedIndex(-1);
    } else {
      // Navigate to the docs page at the correct anchor
      const anchor = entry.docsAnchor ?? 'api';
      window.location.assign(`/docs#${anchor}`);
      onClose();
    }
  };

  const handleKey = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setSelectedIndex(p => p < totalItems - 1 ? p + 1 : 0); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setSelectedIndex(p => p > 0 ? p - 1 : totalItems - 1); }
    else if (e.key === 'Enter' && selectedIndex >= 0) {
      e.preventDefault();
      if (mode === 'commands' && filtered[selectedIndex]) {
        filtered[selectedIndex].action();
        onClose();
      } else if ((mode === 'docs' || mode === 'submenu') && filteredDocs[selectedIndex]) {
        navigateToEntry(filteredDocs[selectedIndex]);
      }
    }
    else if (e.key === 'Escape') {
      if (mode === 'submenu') { setMode('docs'); setSubmenuTag(null); setQuery(''); setSelectedIndex(-1); }
      else if (mode === 'docs') { setMode('commands'); setQuery(''); setSelectedIndex(-1); }
      else onClose();
    }
    else if (e.key === 'Backspace' && query === '') {
      if (mode === 'submenu') { setMode('docs'); setSubmenuTag(null); setSelectedIndex(-1); }
      else if (mode === 'docs') { setMode('commands'); setSelectedIndex(-1); }
    }
  };

  if (!open) return null;

  let idx = 0;

  return (
    <div className="fixed inset-0 z-[500] flex items-start justify-center pt-[20vh]" onClick={onClose}>
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />
      <div className="relative z-10 w-[min(560px,calc(100vw-2rem))] bg-[#0d1017] border border-white/10 rounded-2xl shadow-2xl overflow-hidden" onClick={e => e.stopPropagation()}>
        {/* Input Bar */}
        <div className="flex items-center gap-3 px-4 py-3 border-b border-white/8 bg-[#111520]">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#9b5eff" strokeWidth="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>
          {siteName && (
            <span className="flex items-center gap-1.5 text-white/40 font-mono text-xs flex-shrink-0">
              <span className="text-[#9b5eff] font-semibold">{siteName}</span>
              <span className="text-white/20">/</span>
            </span>
          )}
          {(mode === 'docs' || mode === 'submenu') && (
            <span className="flex items-center gap-1 px-1.5 py-0.5 bg-[#9b5eff]/15 border border-[#9b5eff]/25 rounded text-[10px] font-mono text-[#9b5eff] flex-shrink-0">
              docs
            </span>
          )}
          {mode === 'submenu' && submenuTag && (
            <span className="flex items-center gap-1 px-1.5 py-0.5 bg-amber-500/15 border border-amber-500/25 rounded text-[10px] font-mono text-amber-400 flex-shrink-0">
              {submenuTag.toLowerCase()}
            </span>
          )}
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={e => { setQuery(e.target.value); setSelectedIndex(-1); }}
            onKeyDown={handleKey}
            placeholder={mode === 'submenu' ? `Search ${submenuTag?.toLowerCase() ?? ''} functions...` : mode === 'docs' ? 'Search API endpoints...' : hintText}
            className="flex-1 bg-transparent text-white font-mono text-sm outline-none placeholder:text-white/30"
          />
          <kbd className="px-1.5 py-0.5 text-[9px] font-mono bg-white/5 border border-white/10 rounded text-white/30">ESC</kbd>
        </div>

        {/* Results */}
        <div className="max-h-72 overflow-y-auto py-2">
          {mode === 'commands' && (
            <>
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
              {docsExplorerEnabled && !query && (
                <div className="px-4 py-3 border-t border-white/5 mt-1">
                  <p className="font-mono text-[10px] text-white/25 text-center">
                    Type <kbd className="px-1 py-0.5 bg-white/5 border border-white/10 rounded text-[9px] mx-0.5">/</kbd> <kbd className="px-1 py-0.5 bg-white/5 border border-white/10 rounded text-[9px] mx-0.5">?</kbd> or <kbd className="px-1 py-0.5 bg-white/5 border border-white/10 rounded text-[9px] mx-0.5">#</kbd> to explore API docs
                  </p>
                </div>
              )}
            </>
          )}

          {(mode === 'docs' || mode === 'submenu') && (
            <>
              {docsLoading && (
                <div className="px-4 py-8 text-center font-mono text-sm text-white/30">
                  <span className="inline-block animate-pulse">Loading API docs...</span>
                </div>
              )}
              {!docsLoading && docsGroupOrder.map(tag => (
                <div key={tag}>
                  <div className="px-4 py-1.5 font-mono text-[10px] tracking-[0.14em] uppercase text-white/20">{tag}</div>
                  {docsGroups[tag].map(entry => {
                    const i = idx++;
                    return (
                      <button key={`${entry.method}-${entry.path}`}
                        onClick={() => navigateToEntry(entry)}
                        onMouseEnter={() => setSelectedIndex(i)}
                        className={`w-full flex items-center gap-3 px-4 py-2 text-left transition-colors ${i === selectedIndex ? 'bg-[#9b5eff]/12 text-white' : 'text-white/50 hover:text-white/70'}`}>
                        <span className={`flex-shrink-0 px-1.5 py-0.5 rounded text-[9px] font-mono font-bold ${methodColor(entry.method)}`}>
                          {entry.method}
                        </span>
                        <span className="font-mono text-sm truncate">{entry.path}</span>
                        {entry.hasSubmenu ? (
                          <span className="ml-auto font-mono text-sm text-[#9b5eff]/70">→</span>
                        ) : (
                          <span className="ml-auto font-mono text-[10px] text-white/20 truncate max-w-[150px]">{entry.summary}</span>
                        )}
                      </button>
                    );
                  })}
                </div>
              ))}
              {!docsLoading && filteredDocs.length === 0 && (
                <div className="px-4 py-8 text-center font-mono text-sm text-white/20">
                  {docsEntries.length === 0 ? 'No API docs available' : 'No matching endpoints'}
                </div>
              )}
            </>
          )}

          {mode === 'commands' && filtered.length === 0 && <div className="px-4 py-8 text-center font-mono text-sm text-white/20">No commands found</div>}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-4 py-2 border-t border-white/8 bg-[#111520]">
          <span className="font-mono text-[10px] text-white/20">
            {(mode === 'docs' || mode === 'submenu')
              ? `${filteredDocs.length} endpoint${filteredDocs.length !== 1 ? 's' : ''}`
              : `${filtered.length} command${filtered.length !== 1 ? 's' : ''}`}
          </span>
          <div className="flex gap-2 text-[9px] font-mono text-white/20">
            <span>↑↓ navigate</span>
            <span>↵ select</span>
            {(mode === 'docs' || mode === 'submenu') && <span>⌫ back</span>}
            <span>esc {(mode === 'docs' || mode === 'submenu') ? 'back' : 'close'}</span>
          </div>
        </div>
      </div>
    </div>
  );
}

function methodColor(method: string): string {
  switch (method) {
    case 'GET': return 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/20';
    case 'POST': return 'bg-blue-500/15 text-blue-400 border border-blue-500/20';
    case 'PUT': return 'bg-amber-500/15 text-amber-400 border border-amber-500/20';
    case 'PATCH': return 'bg-orange-500/15 text-orange-400 border border-orange-500/20';
    case 'DELETE': return 'bg-red-500/15 text-red-400 border border-red-500/20';
    default: return 'bg-white/10 text-white/50 border border-white/10';
  }
}

