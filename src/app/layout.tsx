import type { Metadata } from "next";
import { Syne, Atkinson_Hyperlegible, Fira_Code } from "next/font/google";
import "./globals.css";

const syne = Syne({
  variable: "--font-display",
  subsets: ["latin"],
  weight: ["500", "600", "700", "800"],
});

const atkinson = Atkinson_Hyperlegible({
  variable: "--font-sans",
  subsets: ["latin"],
  weight: ["400", "700"],
});

const firaCode = Fira_Code({
  variable: "--font-mono",
  subsets: ["latin"],
  weight: ["400", "500", "700"],
});

export const metadata: Metadata = {
  title: "Vril.js v2.1 — The Security-First React Framework",
  description: "Vril.js v2.1 by VRIL LABS: Post-quantum cryptography (ML-KEM-768, ML-DSA-65), hybrid key exchange, crypto agility with NIST 2035 migration, zero-trust security membrane, and breakthrough browser hardening — built into every layer of the React framework. 22 modules, 200+ exports, zero dependencies, production-ready.",
  keywords: ["Vril.js", "VRIL LABS", "React Framework", "Post-Quantum Cryptography", "PQC", "ML-KEM", "ML-DSA", "Security", "AES-256-GCM", "Hybrid Crypto", "Crypto Agility", "Trusted Types", "Next.js Alternative", "Zero-Trust"],
  authors: [{ name: "VRIL LABS" }],
  openGraph: {
    title: "Vril.js v2.1 — The Security-First React Framework",
    description: "Post-quantum cryptography, hybrid key exchange, and zero-trust security built into every layer of React. 22 modules, 200+ exports, zero dependencies.",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "Vril.js v2.1 — The Security-First React Framework",
    description: "Post-quantum cryptography, hybrid key exchange, and zero-trust security built into every layer of React. 22 modules, 200+ exports, zero dependencies.",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={`${syne.variable} ${atkinson.variable} ${firaCode.variable} antialiased bg-background text-foreground`}>
        {children}
      </body>
    </html>
  );
}
