#!/usr/bin/env python3

import os
import sys
import re
import base64
import hashlib
import getpass
import ast
import random
import string
import builtins

try:
    import astunparse
except Exception:
    astunparse = None

# ========================
# UI helpers
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
    try:
        sys.stdout.write("\x1b[8;{rows};{cols}t".format(rows=32, cols=130))
    except Exception:
        pass
    banner = r"""
░▒▓████████▓▒░▒▓███████▓▒░ ░▒▓██████▓▒░  
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
   ░▒▓█▓▒░   ░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
   ░▒▓█▓▒░   ░▒▓███████▓▒░ ░▒▓██████▓▒░  
    Traceback Obfuscator by CevAPI v1.7
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


def press_enter_to_continue():
    try:
        input("\nPress Enter To Continue...")
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
# obfuscator
# ========================

ALL_BUILTINS = set(dir(builtins))
EXCLUDE_NAMES = []
ALIAS_PREFIX = "TBO_"
USE_SEQUENTIAL = False
alias_counter = 1


def random_alias(prefix=None, length=5):
    global alias_counter, USE_SEQUENTIAL
    if prefix is None:
        prefix = ALIAS_PREFIX
    if USE_SEQUENTIAL:
        alias = f"{prefix}{alias_counter:0{length}d}"
        alias_counter += 1
        return alias
    else:
        digits = string.digits
        suffix = ''.join(random.choices(digits, k=length))
        return prefix + suffix


def starts_with_double_underscore(name: str) -> bool:
    return name.startswith("__")

# Closure conversion and renamer classes (copied from original tbo.py)

class FreeVarsCollector(ast.NodeVisitor):
    def __init__(self):
        self.used = set()
        self.defined = set()
        self.globals = set()
        self.nonlocals = set()

    def visit_FunctionDef(self, node: ast.FunctionDef):
        for arg in node.args.args:
            self.defined.add(arg.arg)
        if node.args.vararg:
            self.defined.add(node.args.vararg.arg)
        for arg in node.args.kwonlyargs:
            self.defined.add(arg.arg)
        if node.args.kwarg:
            self.defined.add(node.args.kwarg.arg)
        for stmt in node.body:
            if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                self.visit(stmt)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        for arg in node.args.args:
            self.defined.add(arg.arg)
        if node.args.vararg:
            self.defined.add(node.args.vararg.arg)
        for arg in node.args.kwonlyargs:
            self.defined.add(arg.arg)
        if node.args.kwarg:
            self.defined.add(node.args.kwarg.arg)
        for stmt in node.body:
            if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                self.visit(stmt)

    def visit_Lambda(self, node: ast.Lambda):
        for arg in node.args.args:
            self.defined.add(arg.arg)
        if node.args.vararg:
            self.defined.add(node.args.vararg.arg)
        for arg in node.args.kwonlyargs:
            self.defined.add(arg.arg)
        if node.args.kwarg:
            self.defined.add(node.args.kwarg.arg)
        self.visit(node.body)

    def visit_ClassDef(self, node: ast.ClassDef):
        self.defined.add(node.name)

    def visit_Global(self, node: ast.Global):
        for name in node.names:
            self.globals.add(name)
            self.defined.add(name)

    def visit_Nonlocal(self, node: ast.Nonlocal):
        for name in node.names:
            self.nonlocals.add(name)
            self.defined.add(name)

    def visit_Name(self, node: ast.Name):
        if isinstance(node.ctx, ast.Load):
            self.used.add(node.id)
        elif isinstance(node.ctx, (ast.Store, ast.Del)):
            self.defined.add(node.id)

    def visit_comprehension(self, node: ast.comprehension):
        self.visit(node.iter)
        for if_ in node.ifs:
            self.visit(if_)
        self._mark_targets_defined(node.target)

    def _mark_targets_defined(self, target):
        if isinstance(target, ast.Name):
            self.defined.add(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._mark_targets_defined(elt)


def compute_free_vars(func_node: ast.AST) -> set:
    c = FreeVarsCollector()
    c.visit(func_node)
    return c.used - c.defined - c.globals - c.nonlocals

class ClosureConversionTransformer(ast.NodeTransformer):
    def __init__(self):
        super().__init__()
        self.nesting = 0

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.nesting += 1
        node = self.generic_visit(node)
        if self.nesting > 1:
            free_vars = compute_free_vars(node)
            if free_vars:
                for var in sorted(free_vars):
                    new_arg = ast.arg(arg=var, annotation=None)
                    node.args.args.append(new_arg)
                    node.args.defaults.append(ast.Name(id=var, ctx=ast.Load()))
        self.nesting -= 1
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self.nesting += 1
        node = self.generic_visit(node)
        if self.nesting > 1:
            free_vars = compute_free_vars(node)
            if free_vars:
                for var in sorted(free_vars):
                    new_arg = ast.arg(arg=var, annotation=None)
                    node.args.args.append(new_arg)
                    node.args.defaults.append(ast.Name(id=var, ctx=ast.Load()))
        self.nesting -= 1
        return node

    def visit_Lambda(self, node: ast.Lambda):
        self.nesting += 1
        node = self.generic_visit(node)
        if self.nesting > 1:
            free_vars = compute_free_vars(node)
            if free_vars:
                for var in sorted(free_vars):
                    new_arg = ast.arg(arg=var, annotation=None)
                    node.args.args.append(new_arg)
                    node.args.defaults.append(ast.Name(id=var, ctx=ast.Load()))
        self.nesting -= 1
        return node

class UniversalRenamer(ast.NodeTransformer):
    def __init__(self):
        super().__init__()
        self.trace_log = {}
        self.changes = []
        self.skip_all_strings = set()
        self.func_params_stack = []

    def visit_Attribute(self, node: ast.Attribute):
        node.value = self.visit(node.value)
        old_attr = node.attr
        if (not starts_with_double_underscore(old_attr)
            and old_attr not in EXCLUDE_NAMES
            and old_attr in self.trace_log):
            node.attr = self._get_new_name(old_attr, getattr(node, "lineno", None))
        return node

    def _get_new_name(self, old_name, lineno=None):
        if starts_with_double_underscore(old_name):
            return old_name
        if old_name in EXCLUDE_NAMES:
            return old_name
        if old_name not in self.trace_log:
            new_alias = random_alias()
            self.trace_log[old_name] = new_alias
            if lineno is not None:
                self.changes.append((lineno, old_name, new_alias))
        else:
            new_alias = self.trace_log[old_name]
            if lineno is not None:
                self.changes.append((lineno, old_name, new_alias))
        return self.trace_log[old_name]

    def visit_Global(self, node: ast.Global):
        new_names = []
        for name in node.names:
            if starts_with_double_underscore(name) or name in EXCLUDE_NAMES:
                new_names.append(name)
            else:
                new_names.append(self._get_new_name(name))
        node.names = new_names
        return node

    def visit_Assign(self, node: ast.Assign):
        if (len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "__all__"
            and isinstance(node.value, ast.List)):
            for elt in node.value.elts:
                if isinstance(elt, ast.Str):
                    self.skip_all_strings.add(elt.s)
        return self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        old_name = node.name
        if not starts_with_double_underscore(old_name) and old_name not in EXCLUDE_NAMES:
            new_name = self._get_new_name(old_name, node.lineno)
            node.name = new_name

        param_names = set()
        if node.args:
            for arg in node.args.args:
                param_names.add(arg.arg)
            if node.args.vararg:
                param_names.add(node.args.vararg.arg)
            for arg in node.args.kwonlyargs:
                param_names.add(arg.arg)
            if node.args.kwarg:
                param_names.add(node.args.kwarg.arg)
        self.func_params_stack.append(param_names)

        old_args = node.args
        node.args = None
        self.generic_visit(node)
        node.args = old_args
        self.func_params_stack.pop()
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        old_name = node.name
        if not starts_with_double_underscore(old_name) and old_name not in EXCLUDE_NAMES:
            new_name = self._get_new_name(old_name, node.lineno)
            node.name = new_name

        param_names = set()
        if node.args:
            for arg in node.args.args:
                param_names.add(arg.arg)
            if node.args.vararg:
                param_names.add(node.args.vararg.arg)
            for arg in node.args.kwonlyargs:
                param_names.add(arg.arg)
            if node.args.kwarg:
                param_names.add(node.args.kwarg.arg)
        self.func_params_stack.append(param_names)

        old_args = node.args
        node.args = None
        self.generic_visit(node)
        node.args = old_args
        self.func_params_stack.pop()
        return node

    def visit_ClassDef(self, node: ast.ClassDef):
        old_name = node.name
        if not starts_with_double_underscore(old_name) and old_name not in EXCLUDE_NAMES:
            new_name = self._get_new_name(old_name, node.lineno)
            node.name = new_name
        self.generic_visit(node)
        return node

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            old_name = alias.asname if alias.asname else alias.name
            if starts_with_double_underscore(old_name) or (old_name in EXCLUDE_NAMES):
                continue
            alias.asname = self._get_new_name(old_name, node.lineno)
        return node

    def visit_ImportFrom(self, node: ast.ImportFrom):
        for alias in node.names:
            old_name = alias.asname if alias.asname else alias.name
            if starts_with_double_underscore(old_name) or (old_name in EXCLUDE_NAMES):
                continue
            alias.asname = self._get_new_name(old_name, node.lineno)
        return node

    def visit_Name(self, node: ast.Name):
        old_id = node.id
        if self.func_params_stack and old_id in self.func_params_stack[-1]:
            return node
        if starts_with_double_underscore(old_id):
            return node
        if old_id in EXCLUDE_NAMES:
            return node
        if old_id in self.skip_all_strings:
            return node

        if isinstance(node.ctx, (ast.Store, ast.Del)):
            node.id = self._get_new_name(old_id, getattr(node, "lineno", None))
        elif isinstance(node.ctx, ast.Load):
            if old_id in self.trace_log:
                node.id = self._get_new_name(old_id, getattr(node, "lineno", None))
            else:
                if old_id in ALL_BUILTINS:
                    node.id = self._get_new_name(old_id, getattr(node, "lineno", None))
        return node

    def visit_Lambda(self, node: ast.Lambda):
        param_names = set(arg.arg for arg in node.args.args)
        if node.args.vararg:
            param_names.add(node.args.vararg.arg)
        for arg in node.args.kwonlyargs:
            param_names.add(arg.arg)
        if node.args.kwarg:
            param_names.add(node.args.kwarg.arg)

        self.func_params_stack.append(param_names)
        self.generic_visit(node)
        self.func_params_stack.pop()
        return node

    def visit_arguments(self, node: ast.arguments):
        saved = None
        if self.func_params_stack:
            saved = self.func_params_stack.pop()
        node.defaults = [self.visit(d) for d in node.defaults]
        if saved is not None:
            self.func_params_stack.append(saved)
        node.kw_defaults = [self.visit(d) if d is not None else None for d in node.kw_defaults]
        return node

    def visit_Call(self, node: ast.Call):
        self.visit(node.func)
        for kw in node.keywords:
            self.visit(kw.value)
        for arg in node.args:
            self.visit(arg)
        return node

    def visit_ListComp(self, node: ast.ListComp):
        for gen in node.generators:
            self.visit(gen)
        self.visit(node.elt)
        return node

    def visit_SetComp(self, node: ast.SetComp):
        for gen in node.generators:
            self.visit(gen)
        self.visit(node.elt)
        return node

    def visit_DictComp(self, node: ast.DictComp):
        for gen in node.generators:
            self.visit(gen)
        self.visit(node.key)
        self.visit(node.value)
        return node

    def visit_GeneratorExp(self, node: ast.GeneratorExp):
        for gen in node.generators:
            self.visit(gen)
        self.visit(node.elt)
        return node

# Pipeline helpers

def remove_docstrings(node):
    if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.body:
        first = node.body[0]
        if isinstance(first, ast.Expr):
            if hasattr(ast, 'Constant'):
                if isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
                    node.body.pop(0)
            else:
                if isinstance(first.value, ast.Str):
                    node.body.pop(0)
    for child in ast.iter_child_nodes(node):
        remove_docstrings(child)
    return node


def rename_everything(code: str):
    tree = ast.parse(code)
    tree = remove_docstrings(tree)
    tree = ClosureConversionTransformer().visit(tree)
    ast.fix_missing_locations(tree)
    transformer = UniversalRenamer()
    new_tree = transformer.visit(tree)
    ast.fix_missing_locations(new_tree)
    if astunparse:
        new_code = astunparse.unparse(new_tree)
    else:
        try:
            new_code = ast.unparse(new_tree)
        except Exception:
            raise RuntimeError("astunparse or ast.unparse is required to run the renamer")
    return new_code, transformer.trace_log, transformer.changes


def insert_builtin_definitions(source: str, trace_log: dict) -> str:
    import_lines = ["import base64\n", "import builtins\n"]
    definitions = []

    for old_name, new_name in trace_log.items():
        if starts_with_double_underscore(old_name):
            continue
        if old_name in EXCLUDE_NAMES:
            continue
        if old_name in ALL_BUILTINS:
            encoded = base64.b64encode(old_name.encode()).decode()
            definitions.append(
                f"{new_name} = getattr(builtins, base64.b64decode(\"{encoded}\").decode())\n"
            )

    if not definitions:
        return source

    lines = source.splitlines(True)
    insert_idx = 1 if (lines and lines[0].startswith("#!")) else 0
    lines[insert_idx:insert_idx] = import_lines + definitions
    return "".join(lines)


def write_changes_log(changes_list, log_filename="trace_log.log"):
    changes_sorted = sorted(changes_list, key=lambda x: x[0])
    with open(log_filename, "w", encoding="utf-8") as f:
        for (lineno, old_name, new_name) in changes_sorted:
            f.write(f"Line {lineno}: {old_name} -> {new_name}\n")
    print(f"TBO Log Saved: '{log_filename}'")


def choose_py_file():
    py_files = [f for f in os.listdir('.') if f.endswith('.py') and os.path.isfile(f)]
    if not py_files:
        print("\nNo .Py Files Found In Current Directory.")
        return None

    print(gradient_text(f"Select A Python File To Transform:", colors))
    for i, fname in enumerate(py_files, start=1):
        print(f"{i}. {fname}")

    while True:
        choice = input(f"\nEnter The Number [1-{len(py_files)}]: ")
        if not choice.isdigit():
            print("\nPlease Enter A Valid Number.")
            continue
        idx = int(choice)
        if 1 <= idx <= len(py_files):
            return py_files[idx-1]
        else:
            print("\nChoice Out Of Range. Try Again.")


def fix_fstring_escapes(code_str: str) -> str:
    # Fix common problematic backslash sequences inside f-strings and other string literals
    code_str = re.sub(r'(:\\)(?=\')', r':\\\\', code_str)
    code_str = re.sub(r'\\(?=\{)', r'\\\\', code_str)
    # Use a raw triple-quoted string so we can include both single and double quotes safely
    code_str = re.sub(r"""(?<!\\)\\(?!\\|'|"|n|r|t|b|f|v|a)([A-Za-z])""", r'\\\\\1', code_str)
    return code_str


def _split_for_embed(s, first=4, alt=3):
    parts = []
    i = 0
    toggle = True
    while i < len(s):
        n = first if toggle else alt
        parts.append(s[i:i+n])
        i += n
        toggle = not toggle
    return parts


def insert_encrypted_traceback_hook(source: str, enable: bool, use_env: bool, env_name: str, embedded_passphrase: str) -> str:
    if not enable:
        return source
    lines = source.splitlines(True)
    insert_idx = 1 if (lines and lines[0].startswith("#!")) else 0
    magic_b64 = base64.b64encode(b'TBOTB1').decode('ascii')
    magic_parts = _split_for_embed(magic_b64)
    pre_secret_lines = []
    if use_env:
        secret_line = f"_TBO_TB_SECRET = _tbo_os.environ.get('{env_name}')\n"
    else:
        b64_secret = base64.b64encode((embedded_passphrase or "").encode('utf-8')).decode('ascii')
        sec_parts = _split_for_embed(b64_secret)
        for i, p in enumerate(sec_parts):
            pre_secret_lines.append(f"_tbo_kp_{i} = '{p}'\n")
        join_expr = " + ".join([f"_tbo_kp_{i}" for i in range(len(sec_parts))])
        secret_line = f"_TBO_TB_SECRET = _tbo_b64.b64decode({join_expr}).decode('utf-8')\n"

    prelude = []
    prelude.append("# TBO Encrypted Traceback Hook\n")
    prelude.append("import sys as _tbo_sys, os as _tbo_os, base64 as _tbo_b64, hashlib as _tbo_hashlib, traceback as _tbo_tb\n")

    for i, p in enumerate(magic_parts):
        prelude.append(f"_tbo_mg_{i} = '{p}'\n")
    prelude.append(f"_TBO_MAGIC = _tbo_b64.b64decode(" + " + ".join([f"_tbo_mg_{i}" for i in range(len(magic_parts))]) + ")\n")

    prelude.extend(pre_secret_lines)
    prelude.append(secret_line)
    prelude.append("_TBO_TB_ITER = 100000\n")
    prelude.append("def _tbo_kdf(secret, salt):\n")
    prelude.append("    if not secret:\n")
    prelude.append("        return None\n")
    prelude.append("    if not isinstance(secret, (bytes, bytearray)):\n")
    prelude.append("        secret = str(secret or '').encode('utf-8')\n")
    prelude.append("    try:\n")
    prelude.append("        return _tbo_hashlib.pbkdf2_hmac('sha256', secret, salt, _TBO_TB_ITER, dklen=32)\n")
    prelude.append("    except Exception:\n")
    prelude.append("        return None\n")
    prelude.append("def _tbo_keystream(n, key, salt):\n")
    prelude.append("    if not key or not isinstance(key, (bytes, bytearray)):\n")
    prelude.append("        return None\n")
    prelude.append("    out = bytearray()\n")
    prelude.append("    counter = 0\n")
    prelude.append("    while len(out) < n:\n")
    prelude.append("        blk = _tbo_hashlib.sha256(key + salt + counter.to_bytes(4, 'big')).digest()\n")
    prelude.append("        out.extend(blk)\n")
    prelude.append("        counter += 1\n")
    prelude.append("    return bytes(out[:n])\n")
    prelude.append("def _tbo_encrypt(text, secret):\n")
    prelude.append("    try:\n")
    prelude.append("        if not secret:\n")
    prelude.append("            return None\n")
    prelude.append("        data = text.encode('utf-8', errors='replace')\n")
    prelude.append("        salt = _tbo_hashlib.sha256((_tbo_os.getenv('TBO_TB_SALT') or '').encode('utf-8')).digest()[:16] if _tbo_os.getenv('TBO_TB_SALT') else _tbo_os.urandom(16)\n")
    prelude.append("        key  = _tbo_kdf(secret, salt)\n")
    prelude.append("        if not key:\n")
    prelude.append("            return None\n")
    prelude.append("        ks = _tbo_keystream(len(data), key, salt)\n")
    prelude.append("        if ks is None:\n")
    prelude.append("            return None\n")
    prelude.append("        ct  = bytes(a ^ b for a, b in zip(data, ks))\n")
    prelude.append("        blob = _TBO_MAGIC + salt + ct\n")
    prelude.append("        return _tbo_b64.b64encode(blob).decode('ascii')\n")
    prelude.append("    except Exception:\n")
    prelude.append("        return None\n")
    prelude.append("def _tbo_excepthook(exc_type, exc, tb):\n")
    prelude.append("    try:\n")
    prelude.append("        txt = ''.join(_tbo_tb.format_exception(exc_type, exc, tb))\n")
    prelude.append("        enc = _tbo_encrypt(txt, _TBO_TB_SECRET)\n")
    prelude.append("    except Exception:\n")
    prelude.append("        enc = None\n")
    prelude.append("    if enc:\n")
    prelude.append("        _tbo_sys.stderr.write(enc + '\\n')\n")
    prelude.append("    else:\n")
    prelude.append("        _tbo_sys.stderr.write('TBO: encrypted traceback unavailable (missing key)\\n')\n")
    prelude.append("    _tbo_sys.stderr.flush()\n")
    prelude.append("    _tbo_sys.exit(1)\n")
    prelude.append("_tbo_sys.excepthook = _tbo_excepthook\n")

    lines[insert_idx:insert_idx] = prelude
    return "".join(lines)

# TBO interactive flow

def tbo_transform():
    os.system("cls" if os.name == "nt" else "clear")
    from sys import stdout
    stdout.write(print_banner())

    infile = choose_py_file()
    if not infile:
        press_enter_to_continue()
        return

    alias_input = input("Enter Alias Prefix (Press Enter For Default 'TBO_'): ")
    if alias_input.strip():
        global ALIAS_PREFIX
        ALIAS_PREFIX = alias_input.strip() + "_"

    seq_choice = input("Use Sequential Numbers Instead Of Random? (Y/N, Default N): ")
    global USE_SEQUENTIAL
    if seq_choice.lower().startswith('y'):
        USE_SEQUENTIAL = True
    else:
        USE_SEQUENTIAL = False

    exclude_input = input("Enter Names To Exclude, Comma-Separated (Or Press Enter For None): ")
    if exclude_input.strip():
        names = [n.strip() for n in exclude_input.split(",")]
        global EXCLUDE_NAMES
        EXCLUDE_NAMES = names
    else:
        EXCLUDE_NAMES.clear()

    base, ext = os.path.splitext(infile)
    outfile = base + "_tbo.py"
    log_file = f"{base}_tracelog.log"

    try:
        with open(infile, "r", encoding="utf-8") as f:
            code = f.read()
    except Exception as e:
        print(f"Failed to read {infile}: {e}")
        press_enter_to_continue()
        return

    try:
        new_code, trace_log, changes = rename_everything(code)
    except Exception as e:
        print(f"Error during rename: {e}")
        press_enter_to_continue()
        return

    final_code = insert_builtin_definitions(new_code, trace_log)
    final_code = fix_fstring_escapes(final_code)

    tbq = input("Inject Encrypted-Traceback Hook Into Output? (Y/N, Default N): ").strip().lower()
    if tbq.startswith('y'):
        use_env = True
        env_name = "TBO_TB_KEY"
        passphrase = ""
        ue = input("Use Environment Variable For Key? (Y/N, Default Y): ").strip().lower()
        if ue and ue.startswith('n'):
            use_env = False
            print(gradient_text("Note: The Passphrase Will Be Stored As Plaintext Within The Python File.", colors2))
            passphrase = input("Enter Passphrase To Embed In Output: ").strip()
            if not passphrase:
                print("Empty Passphrase; Encrypted Traceback Will Not Be Installed.")
            else:
                final_code = insert_encrypted_traceback_hook(final_code, enable=True, use_env=False, env_name=env_name, embedded_passphrase=passphrase)
        else:
            env_in = input(f"Env Var Name For Key (Default {env_name}): ").strip()
            if env_in:
                env_name = env_in
            final_code = insert_encrypted_traceback_hook(final_code, enable=True, use_env=True, env_name=env_name, embedded_passphrase="")

    try:
        with open(outfile, "w", encoding="utf-8") as out:
            out.write(final_code)
    except Exception as e:
        print(f"Failed to write output file: {e}")
        press_enter_to_continue()
        return

    print(gradient_text(f"\nTransformed '{infile}' -> '{outfile}'", colors3))
    write_changes_log(changes, log_file)
    press_enter_to_continue()

# ========================
# de-obfuscator
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
    items = sorted(reverse_map.items(), key=lambda kv: len(kv[0]), reverse=True)
    for obf, orig in items:
        text = re.sub(r"\b" + re.escape(obf) + r"\b", orig, text)
    return text


def tbd_flow(mode):
    # mode: "Paste", "Pick File", "Deobfuscate-Only"
    os.system("cls" if os.name == "nt" else "clear")
    from sys import stdout
    stdout.write(print_banner())

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
            press_enter_to_continue()
            return
    elif mode == "Pick File":
        tb_file = pick_traceback_file()
        if not tb_file:
            print("Nothing To Do.")
            press_enter_to_continue()
            return
        try:
            with open(tb_file, "r", encoding="utf-8", errors="replace") as fh:
                data = fh.read()
        except Exception as e:
            print("Failed To Read File: %s" % e)
            press_enter_to_continue()
            return
    else:
        # Deobfuscate-only
        src_choice = choose_from_list(
            "\nDeobfuscate-Only Mode: Choose Source",
            ["Paste text", "Pick File"]
        )
        if src_choice == "Paste text":
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
                press_enter_to_continue()
                return
        else:
            tb_file = pick_traceback_file()
            if not tb_file:
                print("Nothing To Do.")
                press_enter_to_continue()
                return
            try:
                with open(tb_file, "r", encoding="utf-8", errors="replace") as fh:
                    data = fh.read()
            except Exception as e:
                print("Failed To Read File: %s" % e)
                press_enter_to_continue()
                return

    # For Paste/Pick File modes ask for password
    if mode in ("Paste", "Pick File"):
        print("\nEnter The Password/Key Used By The App’s Encrypted-Traceback Hook.")
        print("(Leave Empty To Use Env Var TBO_TB_KEY If Set.)")
        try:
            secret = getpass.getpass("Password (Hidden): ")
        except Exception:
            secret = input("Password (Visible): ")
        if not secret:
            secret = os.getenv("TBO_TB_KEY", "")
            if not secret:
                print("\nNo Password Provided And TBO_TB_KEY Not Set.")
                print("Encrypted Lines (Base64 of 'TBOTB1'… e.g. 'UkZUVEIx…') Will NOT Be Decrypted.")
                print("Showing Input As-Is.\n")
    else:
        secret = ""

    use_map = choose_from_list("\nUse A Tracelog For Name Deobfuscation?", ["Yes", "No"])
    reverse_map = {}
    chosen_log = None
    if use_map == "Yes":
        choice = choose_tracelog()
        if choice:
            chosen_log = choice
            reverse_map = load_reverse_map(choice)

    if mode in ("Paste", "Pick File"):
        result, dec_count = process_text_blocks(data, secret)
    else:
        result, dec_count = data, 0

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

    press_enter_to_continue()


def tbd_deobfuscate_file():
    """Deobfuscate an unencrypted traceback by picking a file."""
    os.system("cls" if os.name == "nt" else "clear")
    from sys import stdout
    stdout.write(print_banner())

    tb_file = pick_traceback_file()
    if not tb_file:
        print("Nothing To Do.")
        press_enter_to_continue()
        return
    try:
        with open(tb_file, "r", encoding="utf-8", errors="replace") as fh:
            data = fh.read()
    except Exception as e:
        print("Failed To Read File: %s" % e)
        press_enter_to_continue()
        return

    # no decryption for unencrypted traceback
    secret = ""

    use_map = choose_from_list("\nUse A Tracelog For Name Deobfuscation?", ["Yes", "No"])
    reverse_map = {}
    chosen_log = None
    if use_map == "Yes":
        choice = choose_tracelog()
        if choice:
            chosen_log = choice
            reverse_map = load_reverse_map(choice)

    result, dec_count = data, 0

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

    press_enter_to_continue()


def tbd_deobfuscate_paste():
    """Deobfuscate an unencrypted traceback provided via paste/clipboard."""
    os.system("cls" if os.name == "nt" else "clear")
    from sys import stdout
    stdout.write(print_banner())

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
        press_enter_to_continue()
        return

    # no decryption for unencrypted traceback
    secret = ""

    use_map = choose_from_list("\nUse A Tracelog For Name Deobfuscation?", ["Yes", "No"])
    reverse_map = {}
    chosen_log = None
    if use_map == "Yes":
        choice = choose_tracelog()
        if choice:
            chosen_log = choice
            reverse_map = load_reverse_map(choice)

    result, dec_count = data, 0

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

    press_enter_to_continue()


# Replace main menu with nested choices
def main_menu():
    while True:
        os.system("cls" if os.name == "nt" else "clear")
        from sys import stdout
        stdout.write(print_banner())
        print(gradient_text("Main Menu:", colors))
        print("1. Obfuscate/encrypt traceback in Python file")
        print("2. Decrypt encrypted traceback")
        print("3. Deobfuscate unencrypted traceback")

        print("Q. Quit")

        choice = input("\nEnter choice: ").strip().lower()
        if not choice:
            continue
        if choice == '1':
            tbo_transform()
            continue
        if choice == '2':
            # Decrypt encrypted traceback: prompt for source
            os.system("cls" if os.name == "nt" else "clear")
            from sys import stdout
            stdout.write(print_banner())
            sub = choose_from_list(gradient_text("Choose Input Mode:", colors), ["From file", "From clipboard (paste)"])
            if sub == "From file":
                tbd_flow('Pick File')
            else:
                tbd_flow('Paste')
            continue
        if choice == '3':
            # Deobfuscate unencrypted traceback: prompt for source
            os.system("cls" if os.name == "nt" else "clear")
            from sys import stdout
            stdout.write(print_banner())
            sub = choose_from_list(gradient_text("Choose Input Mode:", colors), ["From file", "From clipboard (paste)"])
            if sub == "From file":
                tbd_deobfuscate_file()
            else:
                tbd_deobfuscate_paste()
            continue
        if choice == 'q':
            print("Goodbye.")
            return
        print("Unknown choice.")
        press_enter_to_continue()

if __name__ == '__main__':
    main_menu()
