export interface VrilMetadata {
  title?: string;
  description?: string;
  keywords?: string[];
  authors?: Array<{ name: string }>;
  openGraph?: {
    title?: string;
    description?: string;
    type?: string;
  };
  twitter?: {
    card?: string;
    title?: string;
    description?: string;
  };
}

