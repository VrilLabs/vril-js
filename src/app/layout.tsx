import type { VrilMetadata } from "@/lib/vril/framework";
import "./globals.css";

export const metadata: VrilMetadata = {
  title: "Vril.js v2.2 — The Security-First React Framework",
  description: "Vril.js v2.2 by VRIL LABS: post-quantum-ready cryptography interfaces (ML-KEM-768, ML-DSA-65), hybrid key exchange, crypto agility with NIST 2035 migration, zero-trust security membrane, and breakthrough browser hardening — built into every layer of the React framework. 22 modules, 200+ exports, zero dependencies, production-ready.",
  keywords: ["Vril.js", "VRIL LABS", "React Framework", "Post-Quantum Cryptography", "PQC", "ML-KEM", "ML-DSA", "Security", "AES-256-GCM", "Hybrid Crypto", "Crypto Agility", "Trusted Types", "Next.js Alternative", "Zero-Trust"],
  authors: [{ name: "VRIL LABS" }],
  openGraph: {
    title: "Vril.js v2.2 — The Security-First React Framework",
    description: "Post-quantum-ready cryptography, hybrid key exchange, and zero-trust security built into every layer of React. 22 modules, 200+ exports, zero dependencies.",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "Vril.js v2.2 — The Security-First React Framework",
    description: "Post-quantum-ready cryptography, hybrid key exchange, and zero-trust security built into every layer of React. 22 modules, 200+ exports, zero dependencies.",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="antialiased bg-background text-foreground">
        {children}
      </body>
    </html>
  );
}
