#!/usr/bin/env python3
"""Pre-publication checker: blocks content that must never reach a public remote.

Blocking categories:
  rule6           confidential operational topics (patterns come from the PRIVATE denylist only)
  deployer        a forbidden deployer address (private denylist)
  retired-address an address from the retired set (private denylist)
  private-key     PEM private keys, 32-byte hex keys in a key context, mnemonics, keystore JSON
  token           API/bot tokens (GitHub, Slack, AWS, Telegram, Anthropic/OpenAI style)
  secret-file     a tracked file named like a key, keystore, passphrase or env file
  internal-ip     an address of an operator host (private denylist)
  key-path        a path into a local key folder (private denylist)
  identity        a private author/committer identity, in commit metadata or in content

Warning categories (reported, never block): private-ip, unknown-ip, host-path, workspace-ref.

The denylist is private and lives OUTSIDE every repository (default
~/.config/bloch-publish-safety/denylist.conf, or --denylist / $BLOCH_PUBLISH_DENYLIST): writing
the forbidden values into a repository would publish them. Without it the checker refuses to run
unless --generic-only is given. The allowlist (publish-allowlist.txt next to this file) holds only
public values. Every reported value is cut to its first 6 characters.

Modes:
  publish_check.py tree REF [--repo DIR]           scan the tree at REF
  publish_check.py commits REVS... [--repo DIR]    scan metadata, messages and added lines of
                                                   the commits `git rev-list REVS...` selects
  publish_check.py files PATH...                   scan working files (for generated documents)
  publish_check.py pre-push REMOTE URL             git pre-push hook (reads refs on stdin)
Exit status: 0 clean (warnings allowed), 1 blocking hits, 2 usage or configuration error.
"""
import argparse
import concurrent.futures
import fnmatch
import ipaddress
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ALLOWLIST = os.path.join(HERE, 'publish-allowlist.txt')
DEFAULT_DENYLIST = os.path.expanduser('~/.config/bloch-publish-safety/denylist.conf')

BLOCKING = {'rule6', 'deployer', 'retired-address', 'private-key', 'token', 'secret-file',
            'internal-ip', 'key-path', 'identity'}
WARNING = {'private-ip', 'unknown-ip', 'host-path', 'workspace-ref'}

IPV4 = re.compile(r'(?<![\w.])((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})(?![\w.]*\d)')
HEX40 = re.compile(r'(?<![0-9a-fA-F])(?:0x)?([0-9a-fA-F]{40})(?![0-9a-fA-F])')
HEX64 = re.compile(r'(?<![0-9a-fA-F])(?:0x)?([0-9a-fA-F]{64})(?![0-9a-fA-F])')
KEY_CONTEXT = re.compile(r'(?i)priv(?:ate)?[_ -]?key|privkey|secret[_ -]?key|signing[_ -]?key|--private-key|'
                         r'\bsk\s*[:=]|seed[_ ]?(?:phrase|hex|key)|\bsecret\s*[:=]|client[_ -]?secret|mnemonic')
PEM = re.compile(r'-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----')
MNEMONIC = re.compile(r'(?i)(?:mnemonic|seed[_ ]?phrase)["\']?\s*[:=]\s*["\']?((?:[a-z]+\s+){11,23}[a-z]+)')
KEYSTORE = re.compile(r'"(?:ciphertext|kdfparams)"\s*:')
TOKENS = [
    re.compile(r'\bghp_[A-Za-z0-9]{36}\b'),
    re.compile(r'\bgithub_pat_[A-Za-z0-9_]{60,}\b'),
    re.compile(r'\bxox[abprs]-[A-Za-z0-9-]{10,}\b'),
    re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
    re.compile(r'\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b'),
    re.compile(r'\bsk-(?:ant-)?[A-Za-z0-9_-]{32,}\b'),
    re.compile(r'\bglpat-[A-Za-z0-9_-]{20}\b'),
]
SECRET_FILE_GLOBS = ['*.sk', 'keystore*', '*passphrase*', '*.pem', '*.key', '.env', '*.p12', '*.pfx',
                     'id_rsa*', 'id_ed25519*', 'id_ecdsa*']
SECRET_FILE_OK = ['*.pem.example', '*.key.example', '*.example', '*.template', '*.md', '*.rs', '*.py',
                  '*.sh', '*.ts', '*.tsx', '*.js', '*.mjs', '*.sol', '*.json', '*.toml']
HOST_PATH = re.compile(r'/home/ubuntu\b|\bubuntu@|/Users/[A-Za-z0-9._-]+|/root/\.ssh')
WORKSPACE_REF = re.compile(r'~/Desktop/|\bagents/\d{1,3}-[\w.-]+|l2dexbridge-\d{8}')


class Config:
    def __init__(self):
        self.rule6 = []            # compiled regexes
        self.deployers = set()     # lowercase 40-hex, no 0x
        self.retired = set()
        self.internal_ips = set()
        self.internal_nets = []
        self.key_paths = []        # compiled regexes
        self.identities = []       # compiled regexes (emails, names, hostnames)
        self.allow_ips = []        # ip networks
        self.allow_values = set()  # lowercase hex without 0x
        self.allow_paths = []      # (category, glob)
        self.have_denylist = False

    def prefilter_ere(self):
        """`git grep -E -i` patterns that together select every line the classifier could flag."""
        pats = [r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',
                r'priv(ate)?[_ -]?key|privkey|secret|signing[_ -]?key|PRIVATE KEY|mnemonic|seed|sk *[:=]',
                r'"(ciphertext|kdfparams)"',
                r'ghp_|github_pat_|xox[abprs]-|AKIA|:AA|sk-|glpat-',
                r'/home/ubuntu|ubuntu@|/Users/|/root/\.ssh|~/Desktop/|agents/[0-9]|l2dexbridge-']
        return pats + [r.pattern_ere for r in self.rule6 + self.key_paths + self.identities]

    def prefilter_fixed(self):
        return sorted(self.deployers | self.retired)


class Pat:
    """A denylist pattern, used both as a case-insensitive Python regex and as a `git grep -E -i`
    prefilter, so it must stay in the subset both dialects read the same way: literal characters,
    `\\.`, `[...]`, `( | )`, `^ $`, `? * +` and `{m,n}`. No `(?`, `\\b`, `\\s`, `\\d` or `\\w`."""
    SUBSET = re.compile(r'(?:[\w ,:;@/~|()\[\]{}?*+.\'"=#^$-]|\\[.()\[\]{}?*+|-])+')

    def __init__(self, text):
        if not self.SUBSET.fullmatch(text) or '(?' in text:
            raise SystemExit(f'denylist pattern outside the ERE/Python common subset: {text[:6]}…')
        self.rx = re.compile(text, re.I)
        self.pattern_ere = text

    def search(self, line):
        return self.rx.search(line)


def load_allowlist(cfg, path):
    with open(path) as fh:
        for raw in fh:
            line = raw.split('#', 1)[0].strip()
            if not line:
                continue
            kind, _, rest = line.partition(' ')
            rest = rest.strip()
            if kind == 'ip':
                cfg.allow_ips.append(ipaddress.ip_network(rest, strict=False))
            elif kind == 'value':
                cfg.allow_values.add(rest.lower().replace('0x', '', 1))
            elif kind == 'path':
                cat, _, glob = rest.partition(' ')
                cfg.allow_paths.append((cat, glob.strip()))
            else:
                raise SystemExit(f'{path}: unknown allowlist entry {kind!r}')


def load_denylist(cfg, path):
    section = None
    with open(path) as fh:
        for raw in fh:
            line = raw.rstrip('\n')
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            m = re.fullmatch(r'\s*\[([\w-]+)\]\s*', line)
            if m:
                section = m.group(1)
                continue
            value = line.strip()
            if section == 'rule6':
                cfg.rule6.append(Pat(value))
            elif section in ('deployer', 'retired-address'):
                h = value.lower()
                h = h[2:] if h.startswith('0x') else h
                if not re.fullmatch(r'[0-9a-f]{40}', h):
                    raise SystemExit(f'{path}: bad address in [{section}]')
                (cfg.deployers if section == 'deployer' else cfg.retired).add(h)
            elif section == 'internal-ip':
                if '/' in value:
                    cfg.internal_nets.append(ipaddress.ip_network(value, strict=False))
                else:
                    cfg.internal_ips.add(str(ipaddress.ip_address(value)))
            elif section == 'key-path':
                cfg.key_paths.append(Pat(value))
            elif section == 'identity':
                cfg.identities.append(Pat(value))
            else:
                raise SystemExit(f'{path}: entry outside a known section')
    cfg.retired |= cfg.deployers
    cfg.have_denylist = True


def allowed_path(cfg, category, path):
    return any((cat == category or cat == '*') and fnmatch.fnmatch(path, glob) for cat, glob in cfg.allow_paths)


def low_entropy(h):
    return len(set(h.lower())) < 8


def classify(cfg, line):
    """Yield (category, value) for every finding on one line of text."""
    for pat in cfg.rule6:
        m = pat.search(line)
        if m:
            yield 'rule6', m.group(0)
    for m in HEX40.finditer(line):
        h = m.group(1).lower()
        if h in cfg.deployers:
            yield 'deployer', '0x' + h
        elif h in cfg.retired:
            yield 'retired-address', '0x' + h
    if PEM.search(line):
        yield 'private-key', PEM.search(line).group(0)
    if KEY_CONTEXT.search(line):
        for m in HEX64.finditer(line):
            h = m.group(1).lower()
            if h not in cfg.allow_values and not low_entropy(h):
                yield 'private-key', '0x' + h
    m = MNEMONIC.search(line)
    if m and m.group(1).lower().split() != ['test'] * 11 + ['junk']:
        yield 'private-key', m.group(1)
    if KEYSTORE.search(line):
        yield 'private-key', KEYSTORE.search(line).group(0)
    for rx in TOKENS:
        for m in rx.finditer(line):
            yield 'token', m.group(0)
    for m in IPV4.finditer(line):
        ip = m.group(1)
        addr = ipaddress.ip_address(ip)
        if ip in cfg.internal_ips or any(addr in n for n in cfg.internal_nets):
            yield 'internal-ip', ip
        elif any(addr in n for n in cfg.allow_ips):
            continue
        elif addr.is_private:
            yield 'private-ip', ip
        else:
            yield 'unknown-ip', ip
    for pat in cfg.key_paths:
        m = pat.search(line)
        if m:
            yield 'key-path', m.group(0)
    for pat in cfg.identities:
        m = pat.search(line)
        if m:
            yield 'identity', m.group(0)
    m = HOST_PATH.search(line)
    if m:
        yield 'host-path', m.group(0)
    m = WORKSPACE_REF.search(line)
    if m:
        yield 'workspace-ref', m.group(0)


class Report:
    def __init__(self):
        self.hits = []

    def add(self, cfg, where, path, lineno, line):
        seen = set()
        for cat, value in classify(cfg, line):
            if path and allowed_path(cfg, cat, path):
                continue
            # One hit per category per line, except distinct addresses (each one matters).
            key = (cat, value.lower() if cat in ('internal-ip', 'deployer', 'retired-address') else '')
            if key in seen:
                continue
            seen.add(key)
            self.hits.append({'category': cat, 'where': where, 'path': path, 'line': lineno,
                              'value': value[:6]})

    def blocking(self):
        return [h for h in self.hits if h['category'] in BLOCKING]


def git(repo, *args, check=True):
    p = subprocess.run(['git', '-C', repo] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and p.returncode not in (0,):
        raise SystemExit(f'git {" ".join(args[:3])}: {p.stderr.decode(errors="replace").strip()}')
    return p


def scan_tree(cfg, repo, ref, report):
    names = git(repo, 'ls-tree', '-r', '--name-only', '-z', ref).stdout.decode(errors='replace').split('\0')
    for name in filter(None, names):
        base = os.path.basename(name)
        if any(fnmatch.fnmatch(base, g) for g in SECRET_FILE_GLOBS) and \
                not any(fnmatch.fnmatch(base, g) for g in SECRET_FILE_OK) and not allowed_path(cfg, 'secret-file', name):
            report.hits.append({'category': 'secret-file', 'where': ref, 'path': name, 'line': 0, 'value': base[:6]})
    seen = {}

    def grep(extra):
        p = git(repo, 'grep', '-I', '-n', '-z', '-i', *extra, ref, check=False)
        if p.returncode not in (0, 1):
            raise SystemExit('git grep failed: ' + p.stderr.decode(errors='replace'))
        return p.stdout.decode(errors='replace')

    jobs = [['-E', '-e', pat] for pat in cfg.prefilter_ere()]
    fixed = cfg.prefilter_fixed()
    if fixed:
        jobs.append(['-F'] + [a for f in fixed for a in ('-e', f)])
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        outputs = list(pool.map(grep, jobs))
    # -z output: REF:PATH\0LINENO\0TEXT\n
    for out in outputs:
        for rec in out.split('\n'):
            parts = rec.split('\0')
            if len(parts) < 3:
                continue
            path = parts[0][len(ref) + 1:] if parts[0].startswith(ref + ':') else parts[0]
            seen[(path, int(parts[1]))] = '\0'.join(parts[2:])
    for (path, lineno), text in sorted(seen.items()):
        report.add(cfg, ref, path, lineno, text)


def scan_commits(cfg, repo, revs, report):
    fmt = '%x00%x00COMMIT %H%n%an <%ae>%n%cn <%ce>%n%B%x00'
    p = git(repo, 'log', '--no-color', '-p', '-U0', '--no-ext-diff', '--format=' + fmt, *revs)
    for chunk in p.stdout.decode(errors='replace').split('\0\0COMMIT ')[1:]:
        head, _, diff = chunk.partition('\0')
        lines = head.split('\n')
        sha = lines[0][:12]
        for ident in lines[1:3]:
            for pat in cfg.identities:
                m = pat.search(ident)
                if m:
                    report.hits.append({'category': 'identity', 'where': sha, 'path': '(commit metadata)',
                                        'line': 0, 'value': m.group(0)[:6]})
        for i, text in enumerate(lines[3:], 1):
            report.add(cfg, sha, '(commit message)', i, text)
        path, lineno = None, 0
        for dl in diff.split('\n'):
            if dl.startswith('+++ '):
                path = dl[6:] if dl.startswith('+++ b/') else None
            elif dl.startswith('@@'):
                m = re.search(r'\+(\d+)', dl)
                lineno = int(m.group(1)) if m else 0
            elif dl.startswith('+') and path:
                report.add(cfg, sha, path, lineno, dl[1:])
                lineno += 1


def scan_files(cfg, paths, report):
    for path in paths:
        with open(path, errors='replace') as fh:
            for i, line in enumerate(fh, 1):
                report.add(cfg, 'file', path, i, line.rstrip('\n'))


def pre_push(cfg, repo, remote, report):
    zero = '0' * 40
    private = git(repo, 'config', '--get-all', 'bloch.privateRemote', check=False).stdout.decode().split()
    if remote in private:
        print(f'publish_check: remote {remote} is marked private (bloch.privateRemote); not checked', file=sys.stderr)
        return
    for raw in sys.stdin:
        parts = raw.split()
        if len(parts) != 4 or parts[1] == zero:
            continue
        local_sha, remote_sha = parts[1], parts[3]
        scan_tree(cfg, repo, local_sha, report)
        if remote_sha != zero and git(repo, 'cat-file', '-e', remote_sha, check=False).returncode == 0:
            scan_commits(cfg, repo, [f'{remote_sha}..{local_sha}'], report)
        else:
            scan_commits(cfg, repo, [local_sha, '--not', f'--remotes={remote}'], report)


def build_config(args):
    cfg = Config()
    load_allowlist(cfg, args.allowlist)
    deny = args.denylist or os.environ.get('BLOCH_PUBLISH_DENYLIST') or DEFAULT_DENYLIST
    if os.path.exists(deny):
        load_denylist(cfg, deny)
    elif not args.generic_only:
        raise SystemExit(f'publish_check: private denylist {deny} not found; refusing to run '
                         '(pass --generic-only to scan with the public rules only)')
    return cfg


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('mode', choices=['tree', 'commits', 'files', 'pre-push'])
    ap.add_argument('targets', nargs='*')
    ap.add_argument('--repo', default='.')
    ap.add_argument('--allowlist', default=DEFAULT_ALLOWLIST)
    ap.add_argument('--denylist')
    ap.add_argument('--generic-only', action='store_true')
    ap.add_argument('--json', action='store_true', help='print hits as JSON lines')
    ap.add_argument('--warnings', action='store_true', help='also print warning hits (counts are always printed)')
    args, extra = ap.parse_known_args(argv)
    targets = args.targets + extra
    try:
        cfg = build_config(args)
    except SystemExit as why:
        print(why, file=sys.stderr)
        return 2
    report = Report()
    if args.mode == 'tree':
        for ref in targets or ['HEAD']:
            scan_tree(cfg, args.repo, ref, report)
    elif args.mode == 'commits':
        if not targets:
            print('commits mode needs rev-list arguments', file=sys.stderr)
            return 2
        scan_commits(cfg, args.repo, targets, report)
    elif args.mode == 'files':
        scan_files(cfg, targets, report)
    else:
        if not targets:
            print('pre-push mode needs REMOTE [URL]', file=sys.stderr)
            return 2
        pre_push(cfg, args.repo, targets[0], report)
    counts = {}
    for h in report.hits:
        counts[h['category']] = counts.get(h['category'], 0) + 1
    for h in report.hits:
        if h['category'] in BLOCKING or args.warnings:
            if args.json:
                print(json.dumps(h, sort_keys=True))
            else:
                print(f"{'BLOCK' if h['category'] in BLOCKING else 'warn '} {h['category']:<15} {h['where'][:12]} "
                      f"{h['path']}:{h['line']} {h['value']}…")
    summary = ', '.join(f'{k} {v}' for k, v in sorted(counts.items())) or 'no hits'
    print(f'publish_check: {summary}' + ('' if cfg.have_denylist else ' (generic rules only: no private denylist)'),
          file=sys.stderr)
    return 1 if report.blocking() else 0


if __name__ == '__main__':
    sys.exit(main())
