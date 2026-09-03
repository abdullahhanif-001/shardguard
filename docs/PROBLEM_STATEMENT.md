# Problem Statement — SCSP

**Official Name:** Semantic Code Supply Chain Poisoning & Multi-File Obfuscation Problem

**DARPA Program:** [SocialCyber — Hybrid AI to Protect Integrity of Open Source Code](https://www.darpa.mil/research/programs/hybrid-ai-to-protect-integrity-of-open-source-code)

**Research Domains:** SocialCyber, Taint Analysis Blindspot

## Problem

Static scanners that analyze files in isolation cannot detect malicious logic fragmented across multiple modules. Each fragment appears benign individually; composition at build/runtime activates hidden backdoors.

This is **semantic blindness at the composition layer** — syntax is visible, cross-file intent is not.

## SCSP Solution

1. **Build graph** — npm lifecycle + import/require edges
2. **Cross-file taint** — two-pass SSA-style propagation (scsp-builtin; Nyx when available)
3. **Fragmentation rules** — string/base64 sharding, multi-file reassembly
4. **Gate-proven validation** — MOCK → bypass → REAL → VPS (no green without attestation)

## Honesty

We detect **reachability of untrusted data to security sinks across files**, not perfect mind-reading (Rice's theorem).
