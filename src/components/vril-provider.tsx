'use client';

import { createContext, useContext, type ReactNode } from 'react';
import { type VrilConfig, DEFAULT_VRIL_CONFIG, createVrilApp } from '@/lib/vril/core';

const VrilContext = createContext<{ config: VrilConfig; version: string }>({
  config: DEFAULT_VRIL_CONFIG,
  version: '1.0.0',
});

export function useVril() { return useContext(VrilContext); }

export function VrilProvider({ children, config: userConfig }: { children: ReactNode; config?: Partial<VrilConfig> }) {
  const app = createVrilApp(userConfig);
  return <VrilContext.Provider value={app}>{children}</VrilContext.Provider>;
}
