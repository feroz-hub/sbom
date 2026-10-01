'use client';

import { createContext, useContext } from 'react';
import type { ConfigurationScope } from '@/lib/api';

export const AiConfigurationScope = createContext<{ scope: ConfigurationScope; key: string; canTest: boolean }>({ scope: 'tenant', key: 'tenant', canTest: true });
export const useAiConfigurationScope = () => useContext(AiConfigurationScope);
