# TBO — Traceback Obfuscator & Traceback Deobfuscator

**A Free alternative to the traceback-protection features in Pyarmor (Paid) and Nuitka (Commercial).**  

TBO is a lightweight layer for **obfuscating Python error tracebacks**. It is intended to be used **with already‑obfuscated builds** created by **PyArmor** or **Nuitka** — **even when you use their free tiers**. Using TBO you **capitalize on the encrypted‑traceback / RFT‑style benefits** without paying for add‑ons: even if someone decrypts the encrypted traceback line, the traceback still falls back to **obfuscated names** (PyArmor‑style), preserving sensitive details.

- Nuitka “Traceback Encryption” (commercial feature reference): <https://nuitka.net/doc/commercial/traceback-encryption.html>  
- PyArmor “RFT Mode”: <https://pyarmor.readthedocs.io/en/latest/topic/rftmode.html>

> **Scope:** TBO protects **tracebacks**. It is **not** a general code obfuscator or compiler. Use PyArmor/Nuitka (free or paid) to harden code; add TBO to **hide or encrypt** what leaks via crash tracebacks.

---

## Screenshots
### Main App
![Main App](https://i.imgur.com/CnCMulV.png)
### Post-Obfuscation
![Post Obfuscation](https://i.imgur.com/FEhPN9Y.png)
### Crashed App Example
![Crashed App Example](https://i.imgur.com/fT43If8.png)
### De-obfuscation
![DeObfuscation](https://i.imgur.com/Tlhwerg.png)

---

## What this is (and what it is not)

- **This is** a **traceback protection layer**:
  - Injects a handler that **replaces plaintext tracebacks with a single encrypted Base64 output**.
  - Can **rename symbols** (AST transform) and records a tracelog (like Pyarmor).
  - Ships a **standalone deobfuscator** that can **decrypt** and/or **de‑alias** tracebacks when you have the key and tracelog.

- **This is not**:
  - A **code obfuscator** - if somebody has the source code it is easily reversable.
  - A replacement for PyArmor/Nuitka in protecting bytecode/binaries.
  - A magic bullet against a determined reverse‑engineer; it limits **leakage via errors/logs**.

**Bottom line:** Use **free** versions of PyArmor or Nuitka to obfuscate/compile your app. **Add TBO** to:
1) **Encrypt** tracebacks in production logs.  
2) If decrypted, it will still leave **obfuscated names** (PyArmor‑style), preserving defense‑in‑depth.

## Okay but what is it though?

It’s a safety layer for crash messages.

When your app breaks, it normally prints a detailed “traceback” that can leak how your code works.

TBO replaces that with an encrypted line that only you (with a key and a map) can turn back into a readable error.

Used together with free PyArmor or Nuitka builds, even if someone decrypts the line, the names they see are still scrambled so you can fix the bug without exposing your code or its functionality.

## Project layout

This repository contains **two console apps**:

- **TBO — Traceback Obfuscator** (`tbo.py`):  
  AST‑based symbol aliasing + optional **encrypted‑traceback** hook injection; emits a **tracelog**.
- **Traceback Deobfuscator** (`tbd-o.py`):  
  Decrypts TBO’s Base64 traceback lines and/or **de‑aliases** names back to originals via the tracelog.

---

## How it works (high level)

### 1) AST transform & tracelog
- Renames selected identifiers (functions, classes, globals, locals, import aliases, builtin refs).
- Skips parameters, dunder names, and user‑excluded symbols; preserves closures via default args when needed.
- Produces:
  - `your_file_tbo.py` (transformed source)
  - `your_file_tracelog.log` (original ↔ obfuscated map)

### 2) Encrypted traceback hook 
On unhandled exceptions, the hook emits **one Base64 line** to `stderr` instead of a plaintext traceback. Internals:

```
MAGIC (b"TBOTB1") || 16-byte salt || XOR(stream(key,salt,counter), plaintext)
key = PBKDF2-HMAC-SHA256(secret, salt, 100000)
```

- Secret source: environment variable (default `TBO_TB_KEY`) or embedded passphrase (not recommended).  
- Salt: random by default; deterministic if `TBO_TB_SALT` is set.  
- Exit: process terminates with status `1` after writing the line.

### 3) Offline recovery (support/debug)
Use `tbd-o.py` to **decrypt** the Base64 line(s) and **de‑alias** names via the tracelog. Can also run in **de‑alias‑only** mode if you already have plaintext logs.

---

## Use Case

### A) PyArmor (free) + TBO
1. Apply TBO to your entry module (choose aliasing + encrypted traceback hook).  
2. Run PyArmor obfuscation as usual on the transformed sources.  
3. Deploy with `TBO_TB_KEY` set. Crashes yield **encrypted** lines in logs.  
4. Use `decipher_traceback.py` + tracelog offline to recover readable traces for support.

### B) Nuitka (free) + TBO
1. Apply TBO to your sources **before** compiling with Nuitka.  
2. Compile with Nuitka normally (no commercial traceback‑encryption add‑on needed).  
3. Deploy with `TBO_TB_KEY`. Crashes yield **encrypted** Base64 lines.  
4. Use `decipher_traceback.py` + tracelog offline to recover readable traces for support.


---

## Requirements

- **Python 3.8+** recommended
- `tbo.py`: `astunparse` on Python < 3.9 (`pip install astunparse`)  
  *(On 3.9+, you can use `ast.unparse`.)*
- `tbd-o.py`: standard library only

---

## Security model & limitations

- **Goal:** prevent **accidental leakage** of code structure and line info via crash tracebacks in logs or user reports.
- **Not a shield** against invasive runtime hooking or memory inspection.
- Keep **`TBO_TB_KEY`** and **`*_tracelog.log`** secure; both are required to fully recover readable traces.
- Rotate keys between deployments where possible.

---

## Relationship to Nuitka & PyArmor (attribution)

TBO is **inspired by** the capabilities of the following projects and meant to **complement** them, especially when you use their **free tiers**:

- **Nuitka — Traceback Encryption (commercial feature)**: TBO provides similar traceback‑encryption behavior for pure‑Python flows and compiled binaries **without requiring the paid add‑on**. See: <https://nuitka.net/doc/commercial/traceback-encryption.html>.  
- **PyArmor — RFT (Runtime Traceback) Mode**: TBO’s workflow intentionally mirrors the idea of hiding stack traces at runtime while enabling **offline recovery** for the developer. See: <https://pyarmor.readthedocs.io/en/latest/topic/rftmode.html>.

**Novelty:** TBO **uses both approaches together**: encrypt at runtime; if decrypted, callers still see **obfuscated names** — netting a layered defense not tied to any vendor’s paid tier.

---

## Troubleshooting

- **No Base64 output on crash:** ensure the encrypted‑traceback hook is injected and `TBO_TB_KEY` is set in the environment.
- **Decryption fails:** confirm the Base64 decodes to a buffer beginning with `TBOTB1`; check the passphrase; verify salt usage.
- **Names not de‑aliased:** verify you selected the correct `*_tracelog.log`; de‑aliasing is longest‑match, whole‑word based.
- **Nuitka build quirks:** apply TBO **before** compiling; ensure the transformed module is the one included in your build.
- **Obfuscated application fails (Incompatibilities):** some apps break when identifiers are renamed (PyArmor notes this too). If behavior regresses after TBO’s renaming, exclude the specific functions/methods/classes (especially reflection-sensitive or dynamically accessed names) via TBO’s ignore/exclude list, and widen exclusions only as needed until the app stabilizes.
