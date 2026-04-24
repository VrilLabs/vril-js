'use client';

import { useState, useEffect, useRef, useCallback, type ReactNode } from 'react';

/* ═══════════════════════════════════════════════════════════════
   Vril.js v2.1 — Showcase Landing Page
   World-class · Security-First · VRIL LABS
   ═══════════════════════════════════════════════════════════════ */

// ─── Vril Logo ──────────────────────────────────────────────────
/**
 * Renders the Vril.js brand logo as an inline SVG.
 * Uses `currentColor` so the logo inherits the parent's text color via Tailwind.
 * @param className - Tailwind size/color classes (default: "w-7 h-7")
 */
function VrilLogoIcon({ className = "w-7 h-7" }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 1365 1365" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
      <path fill="currentColor" stroke="none" d="M 694.733337 245.333374 C 694.200012 324.266724 694.333313 360 695.400024 360 C 696.466675 360 763.400024 338.666748 769.133362 336.400024 C 770.06665 336 748.200012 392.400024 720.466675 461.599976 C 692.733337 530.799988 669.533325 588.799988 669.133362 590.400024 C 668.200012 593.333313 668.333313 593.333313 681.266663 593.466675 C 690.06665 593.466675 697.400024 594.400024 703.666687 596.133362 C 708.866638 597.599976 714.200012 599.06665 715.666687 599.466675 C 717.666687 600 730.06665 591.200012 765.666687 564 C 791.666687 544 824.466675 518.93335 838.599976 508.133362 C 852.599976 497.466675 863.799988 488.266663 863.266663 487.733337 C 862.733337 487.333313 848.733337 480.533325 832.06665 472.666687 C 815.266663 464.799988 801.666687 458 801.666687 457.466675 C 801.666687 457.06665 824.06665 444 851.400024 428.666687 C 905.133362 398.400024 1021.133362 332.800049 1059.533325 310.800049 C 1072.599976 303.333374 1083.533325 297.466675 1083.800049 297.733276 C 1084.06665 298 1073.93335 308.400024 1061.400024 320.666626 C 990.866638 389.599976 919 460.799988 919 461.599976 C 919 462.266663 934.733337 470.533325 953.93335 480.133362 C 988.333313 497.333313 988.866638 497.599976 985.266663 499.466675 C 979.533325 502.533325 804.06665 582 757.93335 602.400024 C 749.666687 606.133362 745 608.93335 745.93335 609.466675 C 747.93158 610.576782 807.071045 628.89917 859.781067 644.983948 C 902.033325 657.877502 940.154175 669.333313 941.400024 669.333313 C 942.466675 669.333313 943 668.533325 942.599976 667.599976 C 937.533325 654 920.200012 601.06665 920.733337 600.533325 C 921.133362 600.133362 948.06665 608.533325 980.599976 619.06665 C 1013 629.733337 1082.333374 652.266663 1134.333374 669.200012 C 1186.466675 686 1231.400024 700.799988 1234.333374 701.866638 C 1239.533325 703.733337 1239.533325 703.866638 1235.666626 703.866638 C 1233.533325 703.866638 1207.666626 702.533325 1178.333374 700.666687 C 1065.93335 693.866638 1001.666687 690.266663 1001 690.93335 C 1000.599976 691.200012 1003 699.599976 1006.333313 709.466675 C 1018.333313 745.466675 1025.266724 768 1024.466675 767.466675 C 1024.06665 767.200012 1009.533325 760.93335 992.333313 753.599976 C 965.133362 742 919.93335 722.533325 794.599976 668.533325 C 778.733337 661.599976 765.266663 656 765 656 C 763.799988 656 765.133362 658.400024 823.666687 764.666687 C 840.200012 794.799988 854.866638 821.599976 864.466675 838.93335 C 869.133362 847.599976 873.266663 854.666626 873.666687 854.533325 C 874.06665 854.533325 881.400024 840 890.06665 822.400024 L 905.799988 790.133362 L 915.93335 808.799988 C 927.533325 830 967.93335 903.866699 978.333313 922.666626 C 985.266663 935.200012 1010.200012 980.533325 1047 1047.333374 C 1057.400024 1066.400024 1066.333374 1082.400024 1066.599976 1082.93335 C 1068.466675 1086.266602 1063.800049 1081.599976 1044.199951 1060.93335 C 1009.666687 1024.533325 911.799988 922.533325 905.93335 916.799988 L 900.599976 911.733337 L 896.733337 918.266663 C 894.733337 922 886.06665 938.266663 877.666687 954.533325 C 869.266663 970.666626 861.93335 984 861.533325 984 C 861 984 859.666687 981.466675 858.599976 978.266663 C 857.533325 975.200012 834.866638 917.733337 808.466675 850.666626 C 781.93335 783.599976 759.533325 726.799988 758.733337 724.666687 C 756.333313 718.266663 755.666687 718.266663 751.799988 724 C 749.799988 727.06665 746.200012 731.733337 743.799988 734.400024 C 739.666687 739.06665 738.466675 743.06665 724.599976 797.333313 C 699.799988 894.533325 689.266663 937.333374 690.06665 938.133301 C 690.466675 938.533325 705.666687 933.866699 723.93335 927.599976 C 742.06665 921.333374 757.133362 916.400024 757.400024 916.666626 C 757.666687 916.93335 739 983.333374 715.799988 1064.266602 C 692.733337 1145.06665 672.333313 1216.666626 670.333313 1223.333374 L 667 1235.333374 L 667.666687 1193.333374 C 669.533325 1077.866699 670.06665 994.666626 668.866638 994.666626 C 668.200012 994.666626 650.599976 1000.400024 629.799988 1007.333374 C 609.133362 1014.266663 592.333313 1019.200012 592.733337 1018.266663 C 593.133362 1017.333374 604.06665 990.266663 617 958 C 630.06665 925.733337 653.133362 868.400024 668.333313 830.533325 L 695.93335 761.599976 L 679.799988 761.06665 C 667.93335 760.533325 661.400024 759.599976 654.866638 757.466675 L 646.06665 754.400024 L 611.533325 780.799988 C 520.200012 850.533325 503.533356 863.200012 501.800018 864.666626 C 500.466705 866 506.200043 869.333374 532.200012 882.133301 C 549.93335 890.666626 564.333313 898.133301 564.333313 898.533325 C 564.333313 898.93335 559.93335 901.733337 554.599976 904.533325 C 530.866638 917.466675 379.399994 1001.733337 308.333344 1041.599976 C 293.266663 1050 279.533325 1057.733398 277.666656 1058.666626 C 274.466675 1060.266602 306.066681 1028.93335 403.266693 934 C 431.533356 906.400024 445.000031 892.266663 443.93335 891.599976 C 443.000031 890.93335 426.866699 882.533325 408.066711 872.799988 L 373.666656 855.200012 L 436.066711 827.333313 C 470.333374 812 525 787.599976 557.400024 773.06665 C 589.93335 758.533325 617.133362 746.666687 617.799988 746.666687 C 624.06665 746.666687 607.93335 741.200012 538.733337 720.133362 C 439.133362 689.733337 420.333374 684.133362 420.333374 685.06665 C 420.333374 685.466675 425.400024 700.666687 431.666687 718.93335 C 437.93335 737.200012 443.000031 752.666687 443.000031 753.333313 C 443.000031 753.866638 414.333374 744.93335 379.399994 733.333313 C 325.799988 715.466675 176.46666 666.799988 136.066666 653.866638 C 129.666672 651.866638 124.599998 650 124.73333 649.866638 C 125 649.599976 148.46666 650.93335 177 652.666687 C 275.533325 658.93335 362.200012 664 362.600006 663.599976 C 362.733337 663.333313 360.866669 656.93335 358.333344 649.200012 C 350.600006 626.266663 338.733337 587.866638 339.133331 587.466675 C 339.399994 587.200012 348.333344 590.799988 359 595.333313 C 472.866699 644.533325 513 661.866638 552.06665 678.93335 C 577.266663 690 598.200012 698.666687 598.466675 698.266663 C 598.866638 697.866638 588.733337 678.799988 575.93335 655.733337 C 563.266663 632.799988 544.466675 598.93335 534.333313 580.666687 C 497.93335 514.799988 490.733368 502 489.93335 501.06665 C 489.400024 500.533325 482.066711 514.533325 473.666687 532.133362 C 465.266693 549.599976 458.066711 564 457.666687 564 C 457.266693 563.866638 453.400024 557.200012 448.866699 548.93335 C 437.266693 527.733337 359.933319 388.93335 305 290.93335 C 300.866669 283.333374 297.533325 277.06665 297.799988 276.800049 C 298.066681 276.666626 309.399994 287.866699 323 301.866699 C 420.733368 402.799988 462.333374 445.333313 463.000031 445.333313 C 463.400024 445.333313 472.066711 429.06665 482.200043 409.200012 C 492.466705 389.466675 501.133362 373.733337 501.666687 374.266663 C 502.200043 374.799988 514.733337 405.866638 529.666687 443.333313 C 571.266663 548.133362 605.93335 633.866638 607 635.200012 C 607.666687 635.733337 608.733337 635.06665 609.533325 633.466675 C 610.333313 632 614.06665 627.06665 617.799988 622.666687 C 623.533325 615.733337 625 612.666687 627.799988 602.266663 C 632.466675 585.06665 675 418 675 416.93335 C 675 416.533325 659.93335 421.200012 641.400024 427.466675 C 623 433.599976 607.666687 438.400024 607.533325 438.266663 C 607.266663 438 622.333313 384.266663 641 318.666626 C 659.666687 253.06665 679.266663 183.866699 684.599976 165.06665 C 689.93335 146.133301 694.599976 130.666626 694.866638 130.666626 C 695.133362 130.666626 695.133362 182.266724 694.733337 245.333374 Z" />
    </svg>
  );
}

// ─── SVG Icons ──────────────────────────────────────────────────
function ShieldIcon({ className = "w-5 h-5" }: { className?: string }) {
  return <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>;
}
function LockIcon({ className = "w-5 h-5" }: { className?: string }) {
  return <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>;
}
function ZapIcon({ className = "w-5 h-5" }: { className?: string }) {
  return <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>;
}
function KeyIcon({ className = "w-5 h-5" }: { className?: string }) {
  return <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="m21 2-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0 3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>;
}
function EyeIcon({ className = "w-5 h-5" }: { className?: string }) {
  return <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>;
}
function ServerIcon({ className = "w-5 h-5" }: { className?: string }) {
  return <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>;
}
function LayersIcon({ className = "w-5 h-5" }: { className?: string }) {
  return <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>;
}
function DiamondIcon({ className = "w-5 h-5" }: { className?: string }) {
  return <svg className={className} viewBox="0 0 24 24" fill="currentColor"><path d="M12 2L2 12l10 10 10-10L12 2z"/></svg>;
}
function TerminalIcon({ className = "w-5 h-5" }: { className?: string }) {
  return <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>;
}
function SearchIcon({ className = "w-4 h-4" }: { className?: string }) {
  return <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>;
}
function CopyIcon({ className = "w-4 h-4" }: { className?: string }) {
  return <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>;
}
function CheckIcon({ className = "w-4 h-4" }: { className?: string }) {
  return <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>;
}
function GithubIcon({ className = "w-5 h-5" }: { className?: string }) {
  return <svg className={className} viewBox="0 0 24 24" fill="currentColor"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>;
}
function BoxIcon({ className = "w-5 h-5" }: { className?: string }) {
  return <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>;
}
function PluginIcon({ className = "w-5 h-5" }: { className?: string }) {
  return <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 2v6m0 8v6M2 12h6m8 0h6"/><circle cx="12" cy="12" r="3"/></svg>;
}
function RouteIcon({ className = "w-5 h-5" }: { className?: string }) {
  return <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="6" cy="19" r="3"/><path d="M9 19h8.5a3.5 3.5 0 0 0 0-7h-11a3.5 3.5 0 0 1 0-7H15"/><circle cx="18" cy="5" r="3"/></svg>;
}
function GlobeIcon({ className = "w-5 h-5" }: { className?: string }) {
  return <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>;
}
function FingerprintIcon({ className = "w-5 h-5" }: { className?: string }) {
  return <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M2 12C2 6.5 6.5 2 12 2a10 10 0 0 1 8 4"/><path d="M5 19.5C5.5 18 6 15 6 12c0-.7.12-1.37.34-2"/><path d="M17.29 21.02c.12-.6.43-2.3.5-3.02"/><path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4"/><path d="M8.65 22c.21-.66.45-1.32.57-2"/><path d="M14 13.12c0 2.38 0 6.38-1 8.88"/><path d="M2 16h.01"/><path d="M21.8 16c.2-2 .131-5.354 0-6"/><path d="M9 6.8a6 6 0 0 1 9 5.2c0 .47 0 1.17-.02 2"/></svg>;
}
function RefreshIcon({ className = "w-5 h-5" }: { className?: string }) {
  return <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21.5 2v6h-6M2.5 22v-6h6M2 11.5a10 10 0 0 1 18.8-4.3M22 12.5a10 10 0 0 1-18.8 4.2"/></svg>;
}
function UsersIcon({ className = "w-5 h-5" }: { className?: string }) {
  return <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>;
}

// ─── Feature Data ───────────────────────────────────────────────
const FEATURES = [
  { icon: <ShieldIcon />, title: 'Post-Quantum Cryptography', desc: 'ML-KEM-768 (FIPS 203) and ML-DSA-65 (FIPS 204) with hybrid key exchange. Quantum-resistant by default.', accent: 'violet' as const },
  { icon: <KeyIcon />, title: 'Hybrid Key Exchange', desc: 'X25519 + ML-KEM-768 hybrid KEM. Classical + post-quantum security in every handshake. Belt and suspenders.', accent: 'teal' as const },
  { icon: <RefreshIcon />, title: 'Crypto Agility', desc: 'NIST 2035 migration paths built in. Algorithm registry, versioning, and automated migration — zero downtime.', accent: 'blue' as const },
  { icon: <LockIcon />, title: '\u03A9Vault Encryption', desc: 'AES-256-GCM + PBKDF2-SHA-512 at 600K iterations. Zero-knowledge client-side encryption with visual KDF progress.', accent: 'amber' as const },
  { icon: <ZapIcon />, title: '\u03A9Signal Reactivity', desc: 'Fine-grained reactive primitives — signal, computed, effect, batch, untrack — with auto dependency tracking. Zero deps.', accent: 'violet' as const },
  { icon: <FingerprintIcon />, title: 'Zero-Trust Membrane', desc: 'Trusted Types, API membrane blocking, DOM XSS prevention. Installed at document-start before any app code runs.', accent: 'teal' as const },
  { icon: <ServerIcon />, title: 'Secure SSR', desc: 'Streaming SSR with SHA-256 integrity validation. Selective hydration. RSC deserialization with type allowlisting.', accent: 'blue' as const },
  { icon: <GlobeIcon />, title: 'Edge Runtime', desc: 'Edge KV, Geo, and Security primitives. Bot detection, IP allowlist/blocklist, edge rate limiting. Multi-CDN.', accent: 'teal' as const },
  { icon: <LayersIcon />, title: 'Build Security', desc: '20-point security audit. SBOM generation (CycloneDX). SRI multi-hash. Sigstore signing. Build integrity verification.', accent: 'amber' as const },
  { icon: <PluginIcon />, title: 'Plugin Architecture', desc: 'Dependency-aware plugin registry. Integrity verification. Permission sandboxing. Lifecycle hooks and middleware chain.', accent: 'violet' as const },
  { icon: <RouteIcon />, title: 'Type-Safe API Routes', desc: 'Zero-dep schema validation. Rate limiting. CSRF protection. Versioning. Composable middleware chain.', accent: 'blue' as const },
  { icon: <UsersIcon />, title: 'RBAC & Auth Primitives', desc: 'Session management with HMAC-SHA-256. JWT-like tokens via Web Crypto. PBKDF2 password hashing. Hierarchical RBAC.', accent: 'amber' as const },
];

// ─── Code Tab Data ──────────────────────────────────────────────
const CODE_TABS = [
  {
    id: 'config',
    label: 'createVrilApp',
    lang: 'typescript',
    code: `import { createVrilApp } from 'vril';

const app = createVrilApp({
  security: {
    trustedTypes: true,
    apiMembrane: true,
    blockedAPIs: ['WebTransport'],
    csp: {
      defaultSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameSrc: ["'none'"],
    },
    headers: {
      strictTransportSecurity:
        'max-age=63072000; preload',
      crossOriginEmbedderPolicy:
        'credentialless',
    },
  },
  crypto: {
    pqcEnabled: true,
    hybridMode: true,
    kdfIterations: 600_000,
  },
});`,
  },
  {
    id: 'pqc',
    label: 'PQC Key Exchange',
    lang: 'typescript',
    code: `import { PQCHandler, HybridKeyExchange } from 'vril';

const pqc = new PQCHandler();

// Generate hybrid keypair
// (X25519 + ML-KEM-768)
const keyPair = await pqc.generateHybridKeyPair();

// Negotiate shared secret
// Classical + Post-Quantum combined
const { combinedSecret } = await new HybridKeyExchange()
  .negotiate();

// Crypto agility: migrate algorithms
// without downtime
const agility = new CryptoAgility();
agility.getRegistry()
  .migrate('x25519', 'ml-kem-768');

agility.getStatus();
// \u2192 8 total, 7 active, 0 deprecated`,
  },
  {
    id: 'vault',
    label: '\u03A9Vault',
    lang: 'typescript',
    code: `import { VrilVault } from 'vril';

const vault = new VrilVault(600_000);

// Encrypt with AES-256-GCM
const bundle = await vault.encrypt(
  'my-passphrase', 'secret message'
);
// \u2192 { v: 2, salt, iv, ciphertext,
//     algorithm: 'AES-256-GCM',
//     kdf: 'PBKDF2-SHA-512',
//     kdfIterations: 600000 }

// Decrypt with GCM verification
const result = await vault.decrypt(
  'my-passphrase', bundle
);
console.log(result.plaintext);
// \u2192 'secret message'

// Rotate passphrase without exposing plaintext
const newBundle = await vault.rotatePassphrase(
  oldPass, newPass, bundle
);`,
  },
  {
    id: 'route',
    label: 'Secure Route',
    lang: 'typescript',
    code: `import { createAPIRoute, withCSRF, withRateLimit } from 'vril';

export const POST = createAPIRoute()
  .method('POST')
  .use(withCSRF())
  .use(withRateLimit({
    maxRequests: 100,
    windowMs: 60_000,
  }))
  .body(schema => schema.object({
    email: schema.string().email(),
    password: schema.string().min(12),
  }))
  .handler(async (ctx) => {
    const { email, password } = ctx.body;

    // PBKDF2-SHA-512 at 600K iterations
    const hash = await PasswordHandler
      .hash(password);

    // HMAC-SHA-256 session token
    const session = await SessionManager
      .create({ userId: user.id });

    return { session, user: user.safe };
  });`,
  },
];

// ─── Comparison Data ────────────────────────────────────────────
const COMPARISON_ROWS = [
  { feature: 'PQC Support', vril: 'yes', nextjs: 'no', remix: 'no', astro: 'no' },
  { feature: 'Crypto Agility', vril: 'yes', nextjs: 'no', remix: 'no', astro: 'no' },
  { feature: 'Zero-Trust Membrane', vril: 'yes', nextjs: 'no', remix: 'no', astro: 'no' },
  { feature: 'Built-in Encryption', vril: 'yes', nextjs: 'no', remix: 'no', astro: 'no' },
  { feature: 'Hybrid KEM', vril: 'yes', nextjs: 'no', remix: 'no', astro: 'no' },
  { feature: 'SSR Integrity Validation', vril: 'yes', nextjs: 'no', remix: 'no', astro: 'no' },
  { feature: 'Build Security Audit', vril: 'yes', nextjs: 'partial', remix: 'no', astro: 'no' },
  { feature: 'Edge Runtime Security', vril: 'yes', nextjs: 'partial', remix: 'no', astro: 'no' },
  { feature: 'Crypto Algorithm Registry', vril: 'yes', nextjs: 'no', remix: 'no', astro: 'no' },
  { feature: 'SBOM Generation', vril: 'yes', nextjs: 'no', remix: 'no', astro: 'no' },
];

// ─── Module Ecosystem Data ─────────────────────────────────────
const MODULE_CATEGORIES = [
  { name: 'Core', color: 'teal', modules: ['core', 'config', 'plugin', 'types'] },
  { name: 'Security', color: 'violet', modules: ['security', 'pqc', 'hybrid', 'vault', 'agility', 'hardening', 'audit'] },
  { name: 'Data', color: 'blue', modules: ['signals', 'state', 'hooks', 'cache'] },
  { name: 'Server', color: 'amber', modules: ['server', 'build', 'router', 'auth', 'api'] },
  { name: 'Platform', color: 'teal', modules: ['ssr', 'streaming', 'edge', 'head', 'diagnostics', 'utils'] },
];

// ─── Security Layers Data ──────────────────────────────────────
const SECURITY_LAYERS = [
  { num: 'L5', name: 'Build-Time Integrity', items: ['SRI Multi-Hash', 'SBOM (CycloneDX)', 'Sigstore Signing'], color: '#f5a623' },
  { num: 'L4', name: 'Application Security', items: ['CSRF Protection', 'XSS Shield', 'Route Guards'], color: '#9b5eff' },
  { num: 'L3', name: 'Cryptographic Layer', items: ['PQC (ML-KEM/ML-DSA)', 'Hybrid KEM', '\u03A9Vault', 'Agility Registry'], color: '#00FFC8' },
  { num: 'L2', name: 'Transport Security', items: ['HSTS Preload', 'CSP Level 3', 'Permissions-Policy'], color: '#0A84FF' },
  { num: 'L1', name: 'Browser Hardening', items: ['COOP/COEP/CORP', 'Trusted Types', 'API Membrane'], color: '#ff4d6a' },
];

// ─── Accent Color Map ──────────────────────────────────────────
const accentMap = {
  teal: { text: 'text-olo-teal', bg: 'bg-olo-teal/12', border: 'border-olo-teal/30', glow: 'glow-teal' },
  amber: { text: 'text-amber', bg: 'bg-amber/12', border: 'border-amber/30', glow: 'glow-amber' },
  violet: { text: 'text-violet', bg: 'bg-violet/12', border: 'border-violet/30', glow: 'glow-violet' },
  blue: { text: 'text-ionic-blue', bg: 'bg-ionic-blue/12', border: 'border-ionic-blue/30', glow: 'glow-blue' },
};

// ─── Animated Counter ──────────────────────────────────────────
function AnimatedCounter({ target, suffix = '' }: { target: string; suffix?: string }) {
  const [display, setDisplay] = useState('0');
  const ref = useRef<HTMLSpanElement>(null);
  const counted = useRef(false);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const obs = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting && !counted.current) {
        counted.current = true;
        const num = parseInt(target.replace(/[^0-9]/g, ''));
        if (isNaN(num) || num === 0) { setDisplay(target); return; }
        let frame = 0;
        const totalFrames = 45;
        const animate = () => {
          frame++;
          const eased = 1 - Math.pow(1 - frame / totalFrames, 3);
          setDisplay(Math.round(num * eased).toString() + suffix);
          if (frame < totalFrames) requestAnimationFrame(animate);
          else setDisplay(target + suffix);
        };
        requestAnimationFrame(animate);
      }
    }, { threshold: 0.3 });
    obs.observe(el);
    return () => obs.disconnect();
  }, [target, suffix]);

  return <span ref={ref}>{display}</span>;
}

// ─── Section Wrapper (scroll reveal) ───────────────────────────
function Section({ id, children, className = '' }: { id: string; children: ReactNode; className?: string }) {
  const ref = useRef<HTMLElement>(null);
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const obs = new IntersectionObserver(([e]) => { if (e.isIntersecting) setVisible(true); }, { threshold: 0.06 });
    obs.observe(el);
    return () => obs.disconnect();
  }, []);

  return (
    <section id={id} ref={ref} className={`py-20 md:py-28 relative ${visible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-8'} transition-all duration-700 ease-out ${className}`}>
      {children}
    </section>
  );
}

// ─── Syntax-Highlighted Code Line ──────────────────────────────
function highlightLine(line: string): ReactNode {
  // Simple manual syntax highlighting
  const parts: ReactNode[] = [];
  let remaining = line;
  let key = 0;

  while (remaining.length > 0) {
    // Comments
    const commentIdx = remaining.indexOf('//');
    if (commentIdx === 0) {
      parts.push(<span key={key++} className="text-white/25 italic">{remaining}</span>);
      remaining = '';
      continue;
    }
    if (commentIdx > 0) {
      parts.push(...highlightTokens(remaining.slice(0, commentIdx), key));
      key += 10;
      parts.push(<span key={key++} className="text-white/25 italic">{remaining.slice(commentIdx)}</span>);
      remaining = '';
      continue;
    }

    // Strings
    const strMatch = remaining.match(/^(["'`])(.*?)\1/);
    if (strMatch && remaining.indexOf(strMatch[0]) === 0) {
      parts.push(<span key={key++} className="text-amber">{strMatch[0]}</span>);
      remaining = remaining.slice(strMatch[0].length);
      continue;
    }

    // Arrow
    if (remaining.startsWith('\u2192')) {
      parts.push(<span key={key++} className="text-olo-teal">{remaining.slice(0, 1)}</span>);
      remaining = remaining.slice(1);
      continue;
    }

    // Process a chunk up to the next special thing
    const nextSpecial = Math.min(
      remaining.indexOf('//') === -1 ? Infinity : remaining.indexOf('//'),
      ...['"', "'", '`'].map(q => { const i = remaining.indexOf(q); return i === -1 ? Infinity : i; })
    );

    if (nextSpecial === Infinity) {
      parts.push(...highlightTokens(remaining, key));
      key += 10;
      remaining = '';
    } else {
      parts.push(...highlightTokens(remaining.slice(0, nextSpecial), key));
      key += 10;
      remaining = remaining.slice(nextSpecial);
    }
  }

  return <>{parts}</>;
}

function highlightTokens(text: string, startKey: number): ReactNode[] {
  const tokens: ReactNode[] = [];
  const keywords = new Set(['import', 'from', 'const', 'let', 'var', 'async', 'await', 'export', 'function', 'return', 'new', 'if', 'else', 'typeof', 'instanceof']);
  const types = new Set(['PQCHandler', 'HybridKeyExchange', 'CryptoAgility', 'VrilVault', 'PasswordHandler', 'SessionManager', 'VrilConfig']);

  // Split by word boundaries
  const regex = /(\b\w+\b|\S)/g;
  let match;
  let key = startKey;

  while ((match = regex.exec(text)) !== null) {
    const word = match[0];
    if (keywords.has(word)) {
      tokens.push(<span key={key++} className="text-violet">{word}</span>);
    } else if (types.has(word)) {
      tokens.push(<span key={key++} className="text-ionic-blue">{word}</span>);
    } else if (/^\d/.test(word)) {
      tokens.push(<span key={key++} className="text-amber">{word}</span>);
    } else if (/^[{}()\[\];,.]$/.test(word)) {
      tokens.push(<span key={key++} className="text-white/30">{word}</span>);
    } else {
      tokens.push(<span key={key++} className="text-white/70">{word}</span>);
    }
  }
  return tokens;
}

// ─── Copy Button ───────────────────────────────────────────────
function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }, [text]);

  return (
    <button onClick={handleCopy} className="absolute top-2.5 right-2.5 p-1.5 rounded-md bg-white/5 border border-white/8 text-white/30 hover:text-white hover:border-white/20 transition-all" aria-label="Copy code">
      {copied ? <CheckIcon className="w-3.5 h-3.5 text-olo-teal" /> : <CopyIcon className="w-3.5 h-3.5" />}
    </button>
  );
}

// ─── Code Block with Tabs ──────────────────────────────────────
function CodeShowcase() {
  const [activeTab, setActiveTab] = useState('config');

  const activeCode = CODE_TABS.find(t => t.id === activeTab)!;

  return (
    <div className="rounded-2xl border border-white/8 bg-[#0a0c10] overflow-hidden">
      {/* Tab bar */}
      <div className="flex items-center border-b border-white/8 bg-[#111520] overflow-x-auto">
        <div className="flex items-center gap-1 px-2 py-1">
          {CODE_TABS.map(tab => (
            <button key={tab.id} onClick={() => setActiveTab(tab.id)}
              className={`px-3 py-2 rounded-lg font-mono text-xs transition-all whitespace-nowrap ${activeTab === tab.id ? 'bg-olo-teal/12 text-olo-teal border border-olo-teal/25' : 'text-white/35 hover:text-white/60 border border-transparent'}`}>
              {tab.label}
            </button>
          ))}
        </div>
        <div className="ml-auto pr-2">
          <CopyButton text={activeCode.code} />
        </div>
      </div>
      {/* Code content */}
      <div className="relative">
        <pre className="p-5 overflow-x-auto text-[13px] leading-[1.7]">
          <code className="font-mono">
            {activeCode.code.split('\n').map((line, i) => (
              <div key={i} className="flex">
                <span className="inline-block w-8 text-right pr-4 text-white/15 select-none flex-shrink-0 text-[12px]">{i + 1}</span>
                <span>{highlightLine(line)}</span>
              </div>
            ))}
          </code>
        </pre>
      </div>
      {/* Output hint */}
      <div className="flex items-center gap-2 px-5 py-2.5 border-t border-white/8 bg-[#0d1017]">
        <span className="w-1.5 h-1.5 rounded-full bg-olo-teal animate-vril-pulse" />
        <span className="font-mono text-[10px] text-white/25 tracking-wider uppercase">Live · Zero dependencies · Web Crypto API</span>
      </div>
    </div>
  );
}

// ─── Terminal Block ────────────────────────────────────────────
function TerminalBlock({ lines }: { lines: string[] }) {
  return (
    <div className="rounded-xl border border-white/8 bg-[#0a0c10] overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-white/8 bg-[#111520]">
        <span className="w-2.5 h-2.5 rounded-full bg-[#ff4d6a]/60" />
        <span className="w-2.5 h-2.5 rounded-full bg-[#f5a623]/60" />
        <span className="w-2.5 h-2.5 rounded-full bg-[#4ade80]/60" />
        <span className="ml-3 font-mono text-[10px] text-white/25 tracking-wider uppercase">terminal</span>
      </div>
      <div className="p-4 font-mono text-[13px] leading-[1.8]">
        {lines.map((line, i) => (
          <div key={i}>
            {line.startsWith('$') ? (
              <>
                <span className="text-olo-teal">$</span>
                <span className="text-white/70">{line.slice(1)}</span>
              </>
            ) : line.startsWith('#') ? (
              <span className="text-white/25 italic">{line}</span>
            ) : (
              <span className="text-white/40">{line}</span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// MAIN PAGE
// ═══════════════════════════════════════════════════════════════
export default function VrilShowcase() {
  const [vaultOpen, setVaultOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [paletteQuery, setPaletteQuery] = useState('');
  const [paletteSelected, setPaletteSelected] = useState(-1);
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const handler = () => setScrolled(window.scrollY > 20);
    window.addEventListener('scroll', handler, { passive: true });
    return () => window.removeEventListener('scroll', handler);
  }, []);

  // Keyboard shortcuts
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { setPaletteOpen(false); setVaultOpen(false); }
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') { e.preventDefault(); setPaletteOpen(p => !p); }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, []);

  // Command palette items
  const commands = [
    { id: 'vault', title: 'Open \u03A9Vault', group: 'Security', action: () => setVaultOpen(true) },
    { id: 'sec-arch', title: 'Go to Security Architecture', group: 'Navigation', action: () => document.getElementById('architecture')?.scrollIntoView({ behavior: 'smooth' }) },
    { id: 'features', title: 'Go to Features', group: 'Navigation', action: () => document.getElementById('features')?.scrollIntoView({ behavior: 'smooth' }) },
    { id: 'modules', title: 'Go to Module Ecosystem', group: 'Navigation', action: () => document.getElementById('modules')?.scrollIntoView({ behavior: 'smooth' }) },
    { id: 'compare', title: 'Go to Comparison', group: 'Navigation', action: () => document.getElementById('comparison')?.scrollIntoView({ behavior: 'smooth' }) },
    { id: 'start', title: 'Go to Getting Started', group: 'Navigation', action: () => document.getElementById('get-started')?.scrollIntoView({ behavior: 'smooth' }) },
    { id: 'copy-install', title: 'Copy Install Command', group: 'Actions', action: () => navigator.clipboard.writeText('npx create-vril-app@latest') },
  ];
  const filteredCommands = commands.filter(c => !paletteQuery.trim() || c.title.toLowerCase().includes(paletteQuery.toLowerCase()));

  return (
    <div className="min-h-screen flex flex-col">
      {/* ═══ NAV ═══════════════════════════════════════════════ */}
      <nav className={`fixed top-0 left-0 right-0 z-[200] h-16 transition-all duration-300 ${scrolled ? 'glass shadow-lg' : 'bg-transparent'}`} style={scrolled ? { borderBottom: '1px solid rgba(255,255,255,0.08)' } : {}}>
        <div className="max-w-7xl mx-auto h-full flex items-center justify-between px-5 gap-6">
          <a href="#" className="flex items-center gap-2.5 text-white no-underline">
            <VrilLogoIcon className="w-7 h-7 text-olo-teal" />
            <span className="font-display font-extrabold text-lg tracking-tight">Vril<span className="text-white/40 font-medium">.js</span></span>
            <span className="hidden sm:inline-flex items-center px-2 py-0.5 bg-olo-teal/10 border border-olo-teal/20 rounded-full font-mono text-[9px] text-olo-teal tracking-wider">v2.1</span>
          </a>

          <div className="hidden md:flex items-center gap-6">
            {['Features', 'Architecture', 'Modules', 'Comparison', 'Docs'].map(item => (
              <a key={item} href={item === 'Docs' ? '/docs' : `#${item.toLowerCase()}`} className="font-sans text-xs uppercase tracking-[0.1em] text-white/40 hover:text-white transition-colors no-underline">{item}</a>
            ))}
          </div>

          <div className="flex items-center gap-3">
            <button onClick={() => setPaletteOpen(true)} className="hidden sm:flex items-center gap-2.5 px-3 py-1.5 bg-white/4 border border-white/10 rounded-lg text-white/40 font-mono text-xs hover:border-violet/40 hover:text-white transition-all min-w-[180px]">
              <SearchIcon className="w-3.5 h-3.5 opacity-60" />
              <span>Search...</span>
              <kbd className="ml-auto px-1.5 py-0.5 text-[9px] bg-white/5 border border-white/10 rounded font-mono">⌘K</kbd>
            </button>
            <button onClick={() => setVaultOpen(true)} className="w-9 h-9 flex items-center justify-center rounded-lg bg-white/4 border border-white/10 text-white/40 hover:text-amber hover:border-amber/40 transition-all" aria-label="Open Vault">
              <LockIcon className="w-4 h-4" />
            </button>
            <a href="#get-started" className="hidden sm:flex items-center gap-2 px-4 py-2 bg-olo-teal text-[#080a0e] font-semibold text-sm rounded-lg border border-olo-teal hover:bg-olo-teal/80 transition-all no-underline">
              Get Started
            </a>
          </div>
        </div>
      </nav>

      <main className="flex-1 pt-16">
        {/* ═══ 1. HERO SECTION ═════════════════════════════════ */}
        <section className="relative py-24 md:py-36 overflow-hidden">
          {/* Background effects */}
          <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[900px] h-[700px] opacity-25 pointer-events-none" style={{ background: 'radial-gradient(ellipse at center, rgba(0,255,200,0.18) 0%, rgba(10,132,255,0.08) 40%, transparent 70%)' }} />

          {/* Orbital rings (CSS-only) */}
          <div className="absolute top-1/2 right-[10%] -translate-y-1/2 hidden lg:block" aria-hidden="true">
            <div className="relative w-72 h-72">
              {/* Outer ring */}
              <div className="absolute inset-0 rounded-full border border-white/5 animate-orbit" />
              {/* Middle ring */}
              <div className="absolute inset-8 rounded-full border border-olo-teal/15 animate-orbit-reverse" style={{ animationDuration: '22s' }} />
              {/* Inner ring */}
              <div className="absolute inset-16 rounded-full border border-violet/20 animate-orbit" style={{ animationDuration: '10s' }} />
              {/* Center symbol */}
              <div className="absolute inset-0 flex items-center justify-center">
                <div className="w-20 h-20 rounded-full bg-gradient-to-br from-olo-teal/20 to-violet/20 border border-olo-teal/30 flex items-center justify-center animate-vril-float">
                  <span className="font-display font-extrabold text-3xl gradient-text">Ω</span>
                </div>
              </div>
              {/* Orbiting dots */}
              <div className="absolute top-0 left-1/2 -translate-x-1/2 -translate-y-1/2 w-3 h-3 rounded-full bg-olo-teal animate-orbit" style={{ boxShadow: '0 0 12px rgba(0,255,200,0.6)' }} />
              <div className="absolute bottom-0 right-0 w-2 h-2 rounded-full bg-violet animate-orbit-reverse" style={{ boxShadow: '0 0 8px rgba(155,94,255,0.6)' }} />
            </div>
          </div>

          <div className="max-w-7xl mx-auto px-5 relative z-10">
            <div className="max-w-3xl">
              {/* Badge */}
              <div className="inline-flex items-center gap-2.5 px-4 py-1.5 bg-olo-teal/8 border border-olo-teal/20 rounded-full mb-8 animate-vril-badge-pulse">
                <span className="w-1.5 h-1.5 rounded-full bg-olo-teal" style={{ boxShadow: '0 0 8px #00FFC8' }} />
                <span className="font-mono text-xs tracking-[0.16em] uppercase text-olo-teal">v2.1.0 — Security-First Evolution</span>
              </div>

              {/* Headline */}
              <h1 className="font-display font-extrabold text-5xl sm:text-6xl md:text-7xl lg:text-8xl leading-[0.92] tracking-[-0.04em] mb-6">
                <span className="gradient-text">Vril.js</span>
              </h1>
              <h2 className="font-display font-extrabold text-3xl sm:text-4xl md:text-5xl leading-[0.95] tracking-[-0.03em] mb-6 text-white/90">
                The Security-First<br />React Framework
              </h2>

              {/* Subtitle */}
              <p className="text-lg md:text-xl text-white/45 leading-relaxed max-w-xl mb-8">
                Post-quantum cryptography, zero-trust membrane, crypto agility, and breakthrough browser hardening — woven into every layer. Zero dependencies. 22 modules. 200+ exports.
              </p>

              {/* CTAs */}
              <div className="flex flex-wrap gap-3 mb-16">
                <a href="#get-started" className="inline-flex items-center gap-2 px-6 py-3 bg-olo-teal text-[#080a0e] font-semibold rounded-lg border border-olo-teal hover:-translate-y-0.5 glow-teal transition-all no-underline">
                  <TerminalIcon className="w-4 h-4" /> Get Started
                </a>
                <a href="https://github.com/VrilLabs/vril-js" target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-2 px-6 py-3 bg-transparent text-white/60 font-semibold rounded-lg border border-white/10 hover:border-white/25 hover:text-white transition-all no-underline">
                  <GithubIcon className="w-4 h-4" /> View on GitHub
                </a>
              </div>

              {/* Animated Stats Bar */}
              <div className="flex flex-wrap items-center gap-x-6 gap-y-2 font-mono text-sm text-white/30">
                <span className="flex items-center gap-2">
                  <AnimatedCounter target="0" /> <span className="text-white/15">Dependencies</span>
                </span>
                <span className="w-1 h-1 rounded-full bg-white/10" />
                <span className="flex items-center gap-2">
                  <AnimatedCounter target="22" /> <span className="text-white/15">Modules</span>
                </span>
                <span className="w-1 h-1 rounded-full bg-white/10" />
                <span className="flex items-center gap-2">
                  <AnimatedCounter target="200" suffix="+" /> <span className="text-white/15">Exports</span>
                </span>
                <span className="w-1 h-1 rounded-full bg-white/10" />
                <span className="flex items-center gap-2 text-olo-teal/60">
                  <span className="w-1.5 h-1.5 rounded-full bg-olo-teal animate-vril-pulse" /> Full PQC
                </span>
              </div>
            </div>
          </div>
        </section>

        {/* ═══ 2. LIVE CODE DEMO ════════════════════════════════ */}
        <Section id="code">
          <div className="max-w-7xl mx-auto px-5">
            <div className="text-center mb-14">
              <span className="font-mono text-xs tracking-[0.16em] uppercase text-ionic-blue">Developer Experience</span>
              <h2 className="font-display font-extrabold text-4xl md:text-5xl tracking-[-0.035em] mt-2 mb-4">Security by Default, Not by Config</h2>
              <p className="text-white/45 text-lg max-w-2xl mx-auto">Zero-config security. Intuitive APIs. Full TypeScript. Every cryptographic operation uses the Web Crypto API — no polyfills, no dependencies.</p>
            </div>

            <div className="max-w-4xl mx-auto">
              <CodeShowcase />
            </div>
          </div>
        </Section>

        {/* ═══ 3. FEATURE GRID ══════════════════════════════════ */}
        <Section id="features">
          <div className="max-w-7xl mx-auto px-5">
            <div className="mb-14">
              <span className="font-mono text-xs tracking-[0.16em] uppercase text-olo-teal">Features</span>
              <h2 className="font-display font-extrabold text-4xl md:text-5xl tracking-[-0.035em] mt-2 mb-4">22 Modules. One Mission.</h2>
              <p className="text-white/45 text-lg max-w-2xl">Security isn&apos;t a feature — it&apos;s the foundation. Every module in Vril.js is built with cryptographic integrity and zero-trust principles from the first line.</p>
            </div>

            <div className="grid sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
              {FEATURES.map((feat, i) => {
                const a = accentMap[feat.accent];
                return (
                  <div key={i} className={`group relative p-5 bg-card border border-white/6 rounded-2xl hover:border-white/12 transition-all duration-300 hover:-translate-y-0.5 ${a.glow}`}>
                    <div className={`w-9 h-9 rounded-lg ${a.bg} ${a.border} border flex items-center justify-center mb-3 ${a.text} group-hover:scale-110 transition-transform`}>
                      {feat.icon}
                    </div>
                    <h3 className="font-display font-bold text-sm text-white mb-1.5">{feat.title}</h3>
                    <p className="text-white/35 text-xs leading-relaxed">{feat.desc}</p>
                  </div>
                );
              })}
            </div>
          </div>
        </Section>

        {/* ═══ 4. SECURITY ARCHITECTURE ════════════════════════ */}
        <Section id="architecture">
          <div className="max-w-7xl mx-auto px-5">
            <div className="text-center mb-14">
              <span className="font-mono text-xs tracking-[0.16em] uppercase text-amber">Security Architecture</span>
              <h2 className="font-display font-extrabold text-4xl md:text-5xl tracking-[-0.035em] mt-2 mb-4">Five Layers of Zero-Trust</h2>
              <p className="text-white/45 text-lg max-w-2xl mx-auto">From browser hardening to build integrity, every layer is enforced by default. No opt-in required. No configuration needed.</p>
            </div>

            <div className="max-w-3xl mx-auto">
              <div className="flex flex-col gap-3">
                {SECURITY_LAYERS.map((layer, i) => (
                  <div key={i} className="group relative p-5 bg-card border border-white/6 rounded-2xl hover:border-white/15 transition-all duration-300 hover:scale-[1.02]">
                    {/* Layer accent bar */}
                    <div className="absolute left-0 top-0 bottom-0 w-1 rounded-l-2xl" style={{ backgroundColor: layer.color }} />
                    <div className="flex items-start gap-4 pl-3">
                      <div className="flex-shrink-0">
                        <span className="font-mono text-[10px] tracking-[0.16em] uppercase font-bold" style={{ color: layer.color }}>{layer.num}</span>
                      </div>
                      <div className="flex-1 min-w-0">
                        <h3 className="font-display font-bold text-white mb-2">{layer.name}</h3>
                        <div className="flex flex-wrap gap-2">
                          {layer.items.map(item => (
                            <span key={item} className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-white/4 border border-white/8 rounded-lg font-mono text-[11px] text-white/50 group-hover:text-white/70 group-hover:border-white/12 transition-colors">
                              <span className="w-1 h-1 rounded-full" style={{ backgroundColor: layer.color }} />
                              {item}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </Section>

        {/* ═══ 5. COMPARISON TABLE ═════════════════════════════ */}
        <Section id="comparison">
          <div className="max-w-7xl mx-auto px-5">
            <div className="text-center mb-14">
              <span className="font-mono text-xs tracking-[0.16em] uppercase text-olo-teal">Comparison</span>
              <h2 className="font-display font-extrabold text-4xl md:text-5xl tracking-[-0.035em] mt-2 mb-4">Why Vril.js?</h2>
              <p className="text-white/45 text-lg max-w-xl mx-auto">No other framework ships with post-quantum cryptography, zero-trust security, and crypto agility built in.</p>
            </div>

            <div className="overflow-x-auto max-w-4xl mx-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-white/10">
                    <th className="text-left py-3 pr-4 font-mono text-[10px] tracking-[0.14em] uppercase text-white/25">Feature</th>
                    <th className="text-center py-3 px-3 font-mono text-[10px] tracking-[0.14em] uppercase text-white/25">Next.js</th>
                    <th className="text-center py-3 px-3 font-mono text-[10px] tracking-[0.14em] uppercase text-white/25">Remix</th>
                    <th className="text-center py-3 px-3 font-mono text-[10px] tracking-[0.14em] uppercase text-white/25">Astro</th>
                    <th className="text-center py-3 px-3 font-mono text-[10px] tracking-[0.14em] uppercase text-olo-teal">Vril.js</th>
                  </tr>
                </thead>
                <tbody>
                  {COMPARISON_ROWS.map(row => (
                    <tr key={row.feature} className="border-b border-white/4 hover:bg-white/2 transition-colors">
                      <td className="py-3 pr-4 text-white/60 font-medium">{row.feature}</td>
                      <td className="py-3 px-3 text-center">
                        {row.nextjs === 'yes' ? <span className="text-olo-teal">✓</span> : row.nextjs === 'partial' ? <span className="text-amber text-xs">⚠</span> : <span className="text-white/15">✗</span>}
                      </td>
                      <td className="py-3 px-3 text-center">
                        {row.remix === 'yes' ? <span className="text-olo-teal">✓</span> : row.remix === 'partial' ? <span className="text-amber text-xs">⚠</span> : <span className="text-white/15">✗</span>}
                      </td>
                      <td className="py-3 px-3 text-center">
                        {row.astro === 'yes' ? <span className="text-olo-teal">✓</span> : row.astro === 'partial' ? <span className="text-amber text-xs">⚠</span> : <span className="text-white/15">✗</span>}
                      </td>
                      <td className="py-3 px-3 text-center">
                        <span className="text-olo-teal font-bold">✓</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </Section>

        {/* ═══ 6. MODULE ECOSYSTEM ═════════════════════════════ */}
        <Section id="modules">
          <div className="max-w-7xl mx-auto px-5">
            <div className="text-center mb-14">
              <span className="font-mono text-xs tracking-[0.16em] uppercase text-violet">Module Ecosystem</span>
              <h2 className="font-display font-extrabold text-4xl md:text-5xl tracking-[-0.035em] mt-2 mb-4">22 Modules. Zero Dependencies.</h2>
              <p className="text-white/45 text-lg max-w-xl mx-auto">Every module is hand-crafted with zero external dependencies. All crypto uses the Web Crypto API. All streaming uses Web Streams.</p>
            </div>

            <div className="grid sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-4">
              {MODULE_CATEGORIES.map(cat => {
                const a = accentMap[cat.color as keyof typeof accentMap];
                return (
                  <div key={cat.name} className="p-5 bg-card border border-white/6 rounded-2xl">
                    <div className="flex items-center gap-2 mb-4">
                      <span className={`w-2 h-2 rounded-full ${a.text.replace('text-', 'bg-')}`} />
                      <h3 className="font-display font-bold text-sm text-white">{cat.name}</h3>
                      <span className="ml-auto font-mono text-[10px] text-white/20">{cat.modules.length}</span>
                    </div>
                    <div className="space-y-1.5">
                      {cat.modules.map(mod => (
                        <div key={mod} className="flex items-center gap-2 px-2.5 py-1.5 bg-white/3 rounded-lg hover:bg-white/6 transition-colors group">
                          <BoxIcon className="w-3 h-3 text-white/15 group-hover:text-white/30 transition-colors flex-shrink-0" />
                          <span className="font-mono text-xs text-white/40 group-hover:text-white/70 transition-colors">{mod}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </Section>

        {/* ═══ 7. GETTING STARTED ══════════════════════════════ */}
        <Section id="get-started">
          <div className="max-w-7xl mx-auto px-5">
            <div className="text-center mb-14">
              <span className="font-mono text-xs tracking-[0.16em] uppercase text-amber">Getting Started</span>
              <h2 className="font-display font-extrabold text-4xl md:text-5xl tracking-[-0.035em] mt-2 mb-4">Deploy in 60 Seconds</h2>
              <p className="text-white/45 text-lg max-w-xl mx-auto">One command. Zero config. Every security feature enabled by default. From zero to production-grade.</p>
            </div>

            <div className="max-w-3xl mx-auto grid md:grid-cols-3 gap-6">
              {/* Step 1 */}
              <div className="relative p-5 bg-card border border-white/6 rounded-2xl">
                <span className="absolute -top-3 -left-2 w-7 h-7 rounded-full bg-olo-teal text-[#080a0e] flex items-center justify-center font-mono text-xs font-bold">1</span>
                <h3 className="font-display font-bold text-white mb-2 mt-1">Install</h3>
                <div className="font-mono text-xs text-olo-teal bg-white/3 p-2 rounded-lg">$ npx create-vril-app@latest</div>
              </div>

              {/* Step 2 */}
              <div className="relative p-5 bg-card border border-white/6 rounded-2xl">
                <span className="absolute -top-3 -left-2 w-7 h-7 rounded-full bg-ionic-blue text-white flex items-center justify-center font-mono text-xs font-bold">2</span>
                <h3 className="font-display font-bold text-white mb-2 mt-1">Configure</h3>
                <div className="font-mono text-[11px] text-white/35 leading-relaxed">Security defaults applied. PQC, CSP, HSTS, Trusted Types — all enabled.</div>
              </div>

              {/* Step 3 */}
              <div className="relative p-5 bg-card border border-white/6 rounded-2xl">
                <span className="absolute -top-3 -left-2 w-7 h-7 rounded-full bg-violet text-white flex items-center justify-center font-mono text-xs font-bold">3</span>
                <h3 className="font-display font-bold text-white mb-2 mt-1">Build</h3>
                <div className="font-mono text-xs text-olo-teal bg-white/3 p-2 rounded-lg">$ vril build --secure</div>
              </div>
            </div>

            {/* Full terminal output */}
            <div className="max-w-2xl mx-auto mt-8">
              <TerminalBlock lines={[
                '# Create a new Vril.js project',
                '$ npx create-vril-app@latest my-secure-app',
                '',
                '✓ Security defaults applied',
                '✓ PQC enabled (ML-KEM-768 + X25519)',
                '✓ CSP Level 3 + Trusted Types',
                '✓ HSTS Preload configured',
                '',
                '$ cd my-secure-app && vril dev',
                '',
                '\u25B8 Ready on http://localhost:3000',
                '\u25B8 Security audit: 20/20 checks passed',
                '\u25B8 SBOM generated: sbom.cyclonedx.json',
              ]} />
            </div>

            <div className="flex flex-wrap justify-center gap-4 mt-10">
              <a href="#" className="inline-flex items-center gap-2 px-6 py-3 bg-olo-teal text-[#080a0e] font-semibold rounded-lg border border-olo-teal hover:-translate-y-0.5 glow-teal transition-all no-underline">
                <TerminalIcon className="w-4 h-4" /> Quick Start Guide
              </a>
              <a href="https://github.com/VrilLabs/vril-js" target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-2 px-6 py-3 bg-transparent text-white/50 font-semibold rounded-lg border border-white/10 hover:border-violet/40 hover:text-violet transition-all no-underline">
                <EyeIcon className="w-4 h-4" /> View on GitHub
              </a>
            </div>
          </div>
        </Section>
      </main>

      {/* ═══ FOOTER ═════════════════════════════════════════════ */}
      <footer className="border-t border-white/8 py-12 mt-auto">
        <div className="max-w-7xl mx-auto px-5">
          <div className="flex flex-col md:flex-row items-start justify-between gap-8">
            <div>
              <div className="flex items-center gap-2 mb-3">
                <VrilLogoIcon className="w-6 h-6 text-olo-teal" />
                <span className="font-display font-extrabold text-white">Vril<span className="text-white/40 font-medium">.js</span></span>
              </div>
              <p className="text-white/30 text-sm max-w-xs">The security-first React framework by VRIL LABS. Post-quantum cryptography built into every layer.</p>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-8 text-sm">
              <div>
                <h4 className="font-mono text-[10px] tracking-[0.14em] uppercase text-white/25 mb-3">Framework</h4>
                <div className="space-y-2">
                  {['Security', 'Crypto', 'Signals', 'Modules'].map(l => (
                    <a key={l} href={`#${l.toLowerCase()}`} className="block text-white/40 hover:text-white transition-colors no-underline">{l}</a>
                  ))}
                </div>
              </div>
              <div>
                <h4 className="font-mono text-[10px] tracking-[0.14em] uppercase text-white/25 mb-3">Resources</h4>
                <div className="space-y-2">
                  {['Documentation', 'API Reference', 'Examples', 'Changelog'].map(l => (
                    <a key={l} href="#" className="block text-white/40 hover:text-white transition-colors no-underline">{l}</a>
                  ))}
                </div>
              </div>
              <div>
                <h4 className="font-mono text-[10px] tracking-[0.14em] uppercase text-white/25 mb-3">Security</h4>
                <div className="space-y-2">
                  {['Security Policy', 'Audit Reports', 'SBOM', 'Advisories'].map(l => (
                    <a key={l} href="#" className="block text-white/40 hover:text-white transition-colors no-underline">{l}</a>
                  ))}
                </div>
              </div>
              <div>
                <h4 className="font-mono text-[10px] tracking-[0.14em] uppercase text-white/25 mb-3">Community</h4>
                <div className="space-y-2">
                  {['GitHub', 'Discord', 'Twitter', 'Blog'].map(l => (
                    <a key={l} href="#" className="block text-white/40 hover:text-white transition-colors no-underline">{l}</a>
                  ))}
                </div>
              </div>
            </div>
          </div>
          <div className="mt-10 pt-6 border-t border-white/5 flex flex-col sm:flex-row items-center justify-between gap-4">
            <p className="font-mono text-[10px] text-white/20 tracking-wider">© 2025-2026 VRIL LABS · ALL RIGHTS RESERVED · FIPS 203/204 COMPLIANT</p>
            <div className="flex items-center gap-4">
              <span className="inline-flex items-center gap-2 px-3 py-1 bg-white/4 border border-white/8 rounded-full font-mono text-[10px] text-white/25">
                <span className="w-1.5 h-1.5 rounded-full bg-olo-teal animate-vril-pulse" />
                Built with Vril.js v2.1.0
              </span>
              <span className="font-mono text-[10px] text-white/15">MIT License</span>
            </div>
          </div>
        </div>
      </footer>

      {/* ═══ VAULT DIALOG ══════════════════════════════════════ */}
      {vaultOpen && <VaultInlineDialog onClose={() => setVaultOpen(false)} />}

      {/* ═══ COMMAND PALETTE ═══════════════════════════════════ */}
      {paletteOpen && (
        <div className="fixed inset-0 z-[500] flex items-start justify-center pt-[20vh]" onClick={() => setPaletteOpen(false)}>
          <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />
          <div className="relative z-10 w-[min(560px,calc(100vw-2rem))] bg-[#0d1017] border border-white/10 rounded-2xl shadow-2xl overflow-hidden" onClick={e => e.stopPropagation()}>
            <div className="flex items-center gap-3 px-4 py-3 border-b border-white/8 bg-[#111520]">
              <SearchIcon className="w-4 h-4 text-violet flex-shrink-0" />
              <input type="text" value={paletteQuery} onChange={e => { setPaletteQuery(e.target.value); setPaletteSelected(-1); }}
                onKeyDown={e => {
                  if (e.key === 'ArrowDown') { e.preventDefault(); setPaletteSelected(p => p < filteredCommands.length - 1 ? p + 1 : 0); }
                  else if (e.key === 'ArrowUp') { e.preventDefault(); setPaletteSelected(p => p > 0 ? p - 1 : filteredCommands.length - 1); }
                  else if (e.key === 'Enter' && paletteSelected >= 0 && filteredCommands[paletteSelected]) { e.preventDefault(); filteredCommands[paletteSelected].action(); setPaletteOpen(false); }
                }}
                placeholder="Type a command..." className="flex-1 bg-transparent text-white font-mono text-sm outline-none placeholder:text-white/30" autoFocus />
              <kbd className="px-1.5 py-0.5 text-[9px] font-mono bg-white/5 border border-white/10 rounded text-white/30">ESC</kbd>
            </div>
            <div className="max-h-72 overflow-y-auto py-2">
              {(() => {
                const groups: Record<string, typeof commands> = {};
                const groupOrder: string[] = [];
                filteredCommands.forEach(cmd => {
                  if (!groups[cmd.group]) { groups[cmd.group] = []; groupOrder.push(cmd.group); }
                  groups[cmd.group].push(cmd);
                });
                let idx = 0;
                return groupOrder.map(group => (
                  <div key={group}>
                    <div className="px-4 py-1.5 font-mono text-[10px] tracking-[0.14em] uppercase text-white/20">{group}</div>
                    {groups[group].map(cmd => {
                      const i = idx++;
                      return (
                        <button key={cmd.id} onClick={() => { cmd.action(); setPaletteOpen(false); }} onMouseEnter={() => setPaletteSelected(i)}
                          className={`w-full flex items-center gap-3 px-4 py-2.5 text-left transition-colors ${i === paletteSelected ? 'bg-violet/12 text-white' : 'text-white/50 hover:text-white/70'}`}>
                          <span className="w-3 h-3 rounded-full bg-white/8 flex-shrink-0" />
                          <span className="font-mono text-sm">{cmd.title}</span>
                        </button>
                      );
                    })}
                  </div>
                ));
              })()}
              {filteredCommands.length === 0 && <div className="px-4 py-8 text-center font-mono text-sm text-white/20">No commands found</div>}
            </div>
            <div className="flex items-center justify-between px-4 py-2 border-t border-white/8 bg-[#111520]">
              <span className="font-mono text-[10px] text-white/20">{filteredCommands.length} command{filteredCommands.length !== 1 ? 's' : ''}</span>
              <div className="flex gap-3 text-[9px] font-mono text-white/20"><span>↑↓ navigate</span><span>↵ select</span><span>esc close</span></div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// VAULT INLINE DIALOG (uses real Web Crypto)
// ═══════════════════════════════════════════════════════════════
function VaultInlineDialog({ onClose }: { onClose: () => void }) {
  const [passphrase, setPassphrase] = useState('');
  const [plaintext, setPlaintext] = useState('');
  const [status, setStatus] = useState<'idle' | 'encrypting' | 'decrypting' | 'done' | 'error'>('idle');
  const [result, setResult] = useState('');
  const [resultLabel, setResultLabel] = useState('');
  const [kdfProgress, setKdfProgress] = useState(0);
  const [strength, setStrength] = useState({ score: 0, max: 6, label: '' });

  const assessStrength = (p: string) => {
    let score = 0;
    if (p.length >= 4) score++;
    if (p.length >= 8) score++;
    if (p.length >= 12) score++;
    if (/[A-Z]/.test(p)) score++;
    if (/[0-9]/.test(p)) score++;
    if (/[^A-Za-z0-9]/.test(p)) score++;
    return { score, max: 6, label: score <= 2 ? 'weak' : score <= 4 ? 'moderate' : 'strong' };
  };

  const handlePass = (v: string) => { setPassphrase(v); setStrength(assessStrength(v)); };

  const deriveKey = async (pass: string, salt: Uint8Array): Promise<CryptoKey> => {
    const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: salt as BufferSource, iterations: 600000, hash: 'SHA-512' }, keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  };

  const ab2b64 = (buffer: ArrayBuffer | Uint8Array): string => {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  };

  const b642ab = (b64: string): ArrayBuffer => {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  };

  const handleEncrypt = async () => {
    if (!passphrase || !plaintext) return;
    setStatus('encrypting'); setKdfProgress(0);
    const iv = setInterval(() => setKdfProgress(p => Math.min(p + Math.random() * 15, 90)), 80);
    try {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const ivBytes = crypto.getRandomValues(new Uint8Array(12));
      const key = await deriveKey(passphrase, salt);
      const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: ivBytes }, key, new TextEncoder().encode(plaintext));
      clearInterval(iv); setKdfProgress(100);
      const bundle = { v: 2, salt: ab2b64(salt), iv: ab2b64(ivBytes), ciphertext: ab2b64(ciphertext), algorithm: 'AES-256-GCM', kdf: 'PBKDF2-SHA-512', kdfIterations: 600000 };
      setResult(JSON.stringify(bundle, null, 2)); setResultLabel('Ciphertext Bundle'); setStatus('done');
    } catch (e) { clearInterval(iv); setResult(e instanceof Error ? e.message : 'Failed'); setResultLabel('Error'); setStatus('error'); }
  };

  const handleDecrypt = async () => {
    if (!passphrase || !plaintext) return;
    setStatus('decrypting'); setKdfProgress(0);
    const ivInterval = setInterval(() => setKdfProgress(p => Math.min(p + Math.random() * 15, 90)), 80);
    try {
      const bundle = JSON.parse(plaintext);
      const salt = new Uint8Array(b642ab(bundle.salt));
      const ivBytes = new Uint8Array(b642ab(bundle.iv));
      const ciphertextBuf = b642ab(bundle.ciphertext);
      const key = await deriveKey(passphrase, salt);
      const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivBytes }, key, ciphertextBuf);
      clearInterval(ivInterval); setKdfProgress(100);
      setResult(new TextDecoder().decode(decrypted)); setResultLabel('Plaintext'); setStatus('done');
    } catch { clearInterval(ivInterval); setResult('Wrong passphrase or corrupted bundle'); setResultLabel('Error'); setStatus('error'); }
  };

  return (
    <div className="fixed inset-0 z-[400] flex items-center justify-center" onClick={onClose}>
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />
      <div className="relative z-10 w-[min(560px,calc(100vw-2rem))] max-h-[min(84dvh,700px)] bg-[#0d1017] border border-white/10 rounded-3xl overflow-hidden shadow-2xl" onClick={e => e.stopPropagation()}>
        <div className="flex items-start justify-between p-5 border-b border-white/8 bg-[#111520]">
          <div className="flex flex-col gap-2">
            <span className="font-mono text-[9px] tracking-[0.14em] uppercase px-2.5 py-0.5 rounded-full text-amber bg-amber/12 border border-amber/30 flex items-center gap-1.5 w-fit">
              <span className="w-1.5 h-1.5 rounded-full bg-current" />Vault
            </span>
            <h3 className="font-bold text-lg text-white">ΩVault Encryption</h3>
            <p className="text-sm text-white/50">AES-256-GCM + PBKDF2-SHA-512 · 600K iterations</p>
          </div>
          <button onClick={onClose} className="w-8 h-8 rounded-full flex items-center justify-center text-white/40 bg-white/4 border border-white/8 hover:text-white hover:rotate-90 transition-all" aria-label="Close">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M18 6L6 18M6 6l12 12"/></svg>
          </button>
        </div>
        <div className="p-6 flex flex-col gap-4 max-h-[50dvh] overflow-y-auto">
          <div className="flex flex-col items-center gap-3 py-2">
            <div className={`w-16 h-16 rounded-full border-2 flex items-center justify-center transition-all ${
              status === 'encrypting' || status === 'decrypting' ? 'border-amber text-amber animate-pulse' :
              status === 'done' ? 'border-success text-success' :
              status === 'error' ? 'border-error text-error' : 'border-white/10 text-white/40'
            }`}>
              <LockIcon className="w-7 h-7" />
            </div>
            <span className="font-mono text-xs text-white/30 tracking-widest uppercase">
              {status === 'idle' ? 'Standing by' : status === 'encrypting' ? 'Sealing...' : status === 'decrypting' ? 'Unsealing...' : status === 'done' ? 'Complete' : 'Failed'}
            </span>
          </div>
          {(status === 'encrypting' || status === 'decrypting') && (
            <div className="space-y-1">
              <div className="flex justify-between text-[10px] font-mono text-white/40"><span>Deriving key (PBKDF2-SHA-512)...</span><span>{Math.round(kdfProgress)}%</span></div>
              <div className="h-1.5 bg-white/5 rounded-full overflow-hidden"><div className="h-full bg-gradient-to-r from-amber to-ionic-blue rounded-full transition-all" style={{ width: `${kdfProgress}%` }} /></div>
            </div>
          )}
          <div className="space-y-1.5">
            <label className="font-mono text-[10px] tracking-[0.14em] uppercase text-white/30">Passphrase</label>
            <input type="password" value={passphrase} onChange={e => handlePass(e.target.value)} className="w-full px-3 py-2 bg-[#161b28] border border-white/10 rounded-lg text-white font-mono text-sm focus:outline-none focus:border-olo-teal transition-colors" placeholder="Enter passphrase" />
            <div className="flex gap-1">{Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className={`h-1 flex-1 rounded-full ${i < strength.score ? strength.score <= 2 ? 'bg-error' : strength.score <= 4 ? 'bg-amber' : 'bg-success' : 'bg-white/5'}`} />
            ))}</div>
          </div>
          <div className="space-y-1.5">
            <label className="font-mono text-[10px] tracking-[0.14em] uppercase text-white/30">Input</label>
            <textarea value={plaintext} onChange={e => setPlaintext(e.target.value)} rows={3} className="w-full px-3 py-2 bg-[#161b28] border border-white/10 rounded-lg text-white font-mono text-sm resize-none focus:outline-none focus:border-olo-teal transition-colors" placeholder="Enter plaintext or paste a ciphertext bundle" />
          </div>
          {result && (
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label className="font-mono text-[10px] tracking-[0.14em] uppercase text-white/30">{resultLabel}</label>
                <CopyButton text={result} />
              </div>
              <pre className="px-3 py-2 bg-[#0a0c10] border border-white/10 rounded-lg text-olo-teal font-mono text-xs overflow-x-auto whitespace-pre-wrap max-h-32">{result}</pre>
            </div>
          )}
        </div>
        <div className="flex items-center justify-between gap-3 px-6 py-4 border-t border-white/8 bg-[#111520]">
          <span className="font-mono text-[10px] text-white/20">AES-256-GCM · PBKDF2-SHA-512 · 600K iter</span>
          <div className="flex gap-2">
            <button onClick={handleEncrypt} disabled={!passphrase || !plaintext || status === 'encrypting'} className="px-4 py-2 bg-amber text-[#080a0e] font-semibold text-sm rounded-lg border border-amber hover:bg-amber/80 transition-all disabled:opacity-40">Seal</button>
            <button onClick={handleDecrypt} disabled={!passphrase || !plaintext || status === 'decrypting'} className="px-4 py-2 bg-transparent text-white/70 font-semibold text-sm rounded-lg border border-white/10 hover:border-olo-teal hover:text-olo-teal transition-all disabled:opacity-40">Unseal</button>
          </div>
        </div>
      </div>
    </div>
  );
}
