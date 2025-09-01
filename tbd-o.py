#!/usr/bin/env python3

import os
import sys
import re
import base64
import hashlib
import getpass

# ========================
# UI 
# ========================

def _lerp(a, b, t):
    return int(a + (b - a) * t)

def make_multi_gradient(stops, steps):

    if steps <= 1:
        return [stops[0]]
    segs = len(stops) - 1
    out = []
    for i in range(steps):
        pos = i * segs / (steps - 1)
        idx = int(pos)
        if idx >= segs:
            idx = segs - 1
            t = 1.0
        else:
            t = pos - idx
        r = _lerp(stops[idx][0], stops[idx + 1][0], t)
        g = _lerp(stops[idx][1], stops[idx + 1][1], t)
        b = _lerp(stops[idx][2], stops[idx + 1][2], t)
        out.append((r, g, b))
    return out


def print_banner() -> str:
    sys.stdout.write("\x1b[8;{rows};{cols}t".format(rows=32, cols=130))
    banner = r"""
▄▄▄█████▓ ██▀███   ▄▄▄       ▄████▄  ▓█████  ▄▄▄▄    ▄▄▄       ▄████▄   ██ ▄█▀ ▒█████   ▄▄▄▄     █████▒
▓  ██▒ ▓▒▓██ ▒ ██▒▒████▄    ▒██▀ ▀█  ▓█   ▀ ▓█████▄ ▒████▄    ▒██▀ ▀█   ██▄█▒ ▒██▒  ██▒▓█████▄ ▓██   ▒ 
▒ ▓██░ ▒░▓██ ░▄█ ▒▒██  ▀█▄  ▒▓█    ▄ ▒███   ▒██▒ ▄██▒██  ▀█▄  ▒▓█    ▄ ▓███▄░ ▒██░  ██▒▒██▒ ▄██▒████ ░ 
░ ▓██▓ ░ ▒██▀▀█▄  ░██▄▄▄▄██ ▒▓▓▄ ▄██▒▒▓█  ▄ ▒██░█▀  ░██▄▄▄▄██ ▒▓▓▄ ▄██▒▓██ █▄ ▒██   ██░▒██░█▀  ░▓█▒  ░ 
  ▒██▒ ░ ░██▓ ▒██▒ ▓█   ▓██▒▒ ▓███▀ ░░▒████▒░▓█  ▀█▓ ▓█   ▓██▒▒ ▓███▀ ░▒██▒ █▄░ ████▓▒░░▓█  ▀█▓░▒█░    
  ▒ ░░   ░ ▒▓ ░▒▓░ ▒▒   ▓▒█░░ ░▒ ▒  ░░░ ▒░ ░░▒▓███▀▒ ▒▒   ▓▒█░░ ░▒ ▒  ░▒ ▒▒ ▓▒░ ▒░▒░▒░ ░▒▓███▀▒ ▒ ░    
    ░      ░▒ ░ ▒░  ▒   ▒▒ ░  ░  ▒    ░ ░  ░▒░▒   ░   ▒   ▒▒ TraceBack De-Obfuscator v1.6░ ░▒   ░  ░      
  ░        ░░   ░   ░   ▒   ░           ░    ░    ░   ░   ▒   ░        ░ ░░ ░ ░ ░ ░ ▒   ░    ░  ░ ░    
            ░           ░  ░░ ░         ░  ░ ░            ░  ░░ ░      ░  ░       ░ ░   ░              
                            ░                     ░           ░                              ░         
    
"""
    os.system("")
    faded_banner = ""

    lines = banner.splitlines()
    stops = [
        (85, 0, 145),
        (122, 87, 176),
        (173, 216, 230),
    ]
    colors = make_multi_gradient(stops, max(1, len(lines)))

    for (line, (r, g, b)) in zip(lines, colors):
        faded_banner += (f"\033[38;2;{r};{g};{b}m{line}\033[0m\n")
    return faded_banner
    
colors = [
    (179, 183, 242),
    (183, 226, 240),
    (183, 226, 240)
]
colors2 = [
    (255, 196, 0),   
    (255, 214, 70),  
    (255, 240, 140)  
]
colors3 = [
    (26, 115, 52),  
    (76, 175, 80),  
    (86, 185, 90),  
]

def gradient_text(text: str, colors: list) -> str:
    os.system("")
    gradient = ""
    color_index = 0
    for char in text:
        if char != " ":
            r, g, b = colors[color_index]
            gradient += f"\033[38;2;{r};{g};{b}m{char}\033[0m"
            color_index = (color_index + 1) % len(colors)
        else:
            gradient += char
    return gradient

def press_enter_to_exit():
    try:
        input("\nPress Enter To Exit...")
    except EOFError:
        pass

def choose_from_list(title, items):
    if title:  
        print(title)
    for i, it in enumerate(items, 1):
        print("%d. %s" % (i, it))
    print("")
    while True:
        s = input("Enter The Number [1-%d]: " % len(items)).strip()
        if not s.isdigit():
            print("Please Enter A Valid Number.")
            continue
        idx = int(s)
        if 1 <= idx <= len(items):
            return items[idx - 1]
        print("Choice Out Of Range. Try Again.")


# ========================
# File picking
# ========================

def list_candidate_files():
    files = [f for f in os.listdir(".") if os.path.isfile(f)]
    preferred_exts = (".txt", ".log", ".out")
    a = [f for f in files if f.lower().endswith(preferred_exts)]
    b = [f for f in files if f not in a]
    return a, b

def pick_traceback_file():
    cand_pref, cand_other = list_candidate_files()
    if not cand_pref and not cand_other:
        print("No Files Found In Current Directory.")
        return None
    groups = []
    if cand_pref:
        groups.append(("Text/Log Files", cand_pref))
    if cand_other:
        groups.append(("All Other Files", cand_other))
    flat = []
    for label, group in groups:
        flat.append("--- %s ---" % label)
        flat.extend(group)
    selectable = [f for f in flat if not f.startswith("---")]
    if not selectable:
        print("No Selectable Files.")
        return None
    return choose_from_list("Select A File To Decode:", selectable)

def find_tracelogs():
    files = [f for f in os.listdir(".") if os.path.isfile(f)]
    return sorted([f for f in files if f.endswith("_tracelog.log")])

def choose_tracelog():
    logs = find_tracelogs()
    options = []
    if logs:
        options.extend(logs)
    options.append("<Enter A Path Manually>")
    options.append("<Do Not Use A Tracelog>")
    choice = choose_from_list("\nSelect A Tracelog For Deobfuscation (Or Skip):", options)
    if choice == "<Do Not Use A Tracelog>":
        return None
    if choice == "<Enter A Path Manually>":
        path = input("Enter tracelog path: ").strip()
        return path if path else None
    return choice

# ========================
# TBO encrypted traceback decode 
# ========================

_MAGIC = b"TBOTB1"
_ITER = 100000  

def kdf(secret, salt):
    if not isinstance(secret, (bytes, bytearray)):
        secret = str(secret or "").encode("utf-8")
    return hashlib.pbkdf2_hmac("sha256", secret, salt, _ITER, dklen=32)

def keystream(n, key, salt):
    out = bytearray()
    ctr = 0
    while len(out) < n:
        out.extend(hashlib.sha256(key + salt + ctr.to_bytes(4, "big")).digest())
        ctr += 1
    return bytes(out[:n])

def try_decrypt_line(line, secret):
    line = line.rstrip("\r\n")
    if not line:
        return None  
    try:
        raw = base64.b64decode(line, validate=True)
    except Exception:
        return None
    if not raw.startswith(_MAGIC):
        return None
    salt = raw[len(_MAGIC):len(_MAGIC)+16]
    ct = raw[len(_MAGIC)+16:]
    key = kdf(secret, salt)
    ks = keystream(len(ct), key, salt)
    pt = bytes(a ^ b for a, b in zip(ct, ks))
    return pt.decode("utf-8", errors="replace")

def process_text_blocks(text, secret):
    out_lines = []
    dec_count = 0
    for line in text.splitlines(True):
        pt = try_decrypt_line(line, secret)
        if pt is None:
            out_lines.append(line)
        else:
            out_lines.append(pt if pt.endswith("\n") else pt + "\n")
            dec_count += 1
    return "".join(out_lines), dec_count

# ========================
# Tracelog mapping (alias -> original)
# ========================

def load_reverse_map(tracelog_path):
    rev = {}
    if not tracelog_path:
        return rev
    if not os.path.isfile(tracelog_path):
        print("Warning: Tracelog Not Found: %s" % tracelog_path)
        return rev
    try:
        with open(tracelog_path, "r", encoding="utf-8") as f:
            for line in f:
                m = re.search(r":\s*(\S+)\s*->\s*(\S+)", line)
                if m:
                    original = m.group(1)
                    obfuscated = m.group(2)
                    rev[obfuscated] = original
    except Exception as e:
        print("Warning: Failed To Read Tracelog: %s" % e)
    return rev

def deobfuscate_names(text, reverse_map):
    if not reverse_map:
        return text
    # Replace longer aliases first to avoid partial overlaps
    items = sorted(reverse_map.items(), key=lambda kv: len(kv[0]), reverse=True)
    for obf, orig in items:
        # word-boundary replacement
        text = re.sub(r"\b" + re.escape(obf) + r"\b", orig, text)
    return text

# ========================
# Main flow
# ========================

def main():
    os.system("cls" if os.name == "nt" else "clear")
    from sys import stdout
    stdout.write(print_banner())

    print(gradient_text(f"Choose Input Mode:", colors))
    mode = choose_from_list(None, ["Paste", "Pick File", "Deobfuscate-Only"])


    data = ""
    # Acquire input text for all modes (paste/file)
    if mode == "Paste":
        print("\nPaste The Obfuscated/Encoded Traceback Line(s) Below.")
        print("Finish By Entering A Blank Line.\n")
        pasted = []
        while True:
            try:
                line = input()
            except EOFError:
                break
            if line == "":
                break
            pasted.append(line)
        data = "\n".join(pasted) + ("\n" if pasted else "")
        if not data.strip():
            print("No Input Provided.")
            press_enter_to_exit()
            return
    elif mode == "Pick File":
        tb_file = pick_traceback_file()
        if not tb_file:
            print("Nothing To Do.")
            press_enter_to_exit()
            return
        try:
            with open(tb_file, "r", encoding="utf-8", errors="replace") as fh:
                data = fh.read()
        except Exception as e:
            print("Failed To Read File: %s" % e)
            press_enter_to_exit()
            return
    else:
        # Deobfuscate-only mode: choose source, but skip decryption entirely
        src_choice = choose_from_list(
            "\nDeobfuscate-Only Mode: Choose Source", 
            ["Paste text", "Pick File"] 
        )
        if src_choice == "Paste Text":  
            print("\nPaste The Text To Deobfuscate, Then Blank Line.")  
            pasted = []
            while True:
                try:
                    line = input()
                except EOFError:
                    break
                if line == "":
                    break
                pasted.append(line)
            data = "\n".join(pasted) + ("\n" if pasted else "")
            if not data.strip():
                print("No Input Provided.")
                press_enter_to_exit()
                return
        else: 
            tb_file = pick_traceback_file() 
            if not tb_file:  
                print("Nothing To Do.") 
                press_enter_to_exit() 
                return 
            try:  
                with open(tb_file, "r", encoding="utf-8", errors="replace") as fh:
                    data = fh.read()
            except Exception as e:
                print("Failed To Read File: %s" % e)
                press_enter_to_exit()
                return

    # Get password for modes 1/2; skip for mode 3 
    if mode in ("Paste", "Pick file"): 
        print("\nEnter The Password/Key Used By The App’s Encrypted-Traceback Hook.")
        print("(Leave Empty To Use Env Var TBO_TB_KEY If Set.)")
        secret = getpass.getpass("Password (Hidden): ")
        if not secret:
            secret = os.getenv("TBO_TB_KEY", "")
            if not secret:
                print("\nNo Password Provided And TBO_TB_KEY Not Set.")
                print("Encrypted Lines (Base64 of 'TBOTB1'… e.g. 'UkZUVEIx…') Will NOT Be Decrypted.")
                print("Showing Input As-Is.\n")
    else:
        secret = "" 

    # Optional: tracelog mapping
    use_map = choose_from_list("\nUse A Tracelog For Name Deobfuscation?", ["Yes", "No"])
    reverse_map = {}
    chosen_log = None
    if use_map == "Yes":
        choice = choose_tracelog()
        if choice:
            chosen_log = choice
            reverse_map = load_reverse_map(choice)

    # Decrypt (if applicable) 
    if mode in ("Paste", "Pick File"): 
        result, dec_count = process_text_blocks(data, secret)
    else:
        result, dec_count = data, 0  

    # Apply tracelog mapping (if provided)
    if reverse_map:
        result = deobfuscate_names(result, reverse_map)

    print(gradient_text(f"\n========= Decoded Output =========\n", colors))
    print(result, end="" if result.endswith("\n") else "\n")
    print(gradient_text(f"\n========= Summary =========\n", colors))
    print("Decrypted Lines: %d" % dec_count)
    if chosen_log:
        print("Deobfuscation Map: %s" % chosen_log)
    else:
        print("Deobfuscation Map: <none>")

    press_enter_to_exit()

if __name__ == "__main__":
    main()

