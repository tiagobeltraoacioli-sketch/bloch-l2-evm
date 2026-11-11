#!/bin/bash
# Install the Bloch L2 mainnet SHADOW producer. REVIEWED BY THE OPERATOR, RUN AS ROOT.
# The producer of record is the settler (settler_v3.py mainnet mode, install-settler-mainnet.py,
# user bloch-l2-mainnet-settler): it writes the canonical L2 database. This unit rebuilds every
# block the settler produced on its OWN database from the native view (+ the settler's DA batch)
# and stops (exit 3) on any difference, before the proof reaches L1. Install after the settler's
# `prepare` (it needs the read group bloch-l2-mainnet-l2read and /var/lib/bloch-l2-mainnet-settler/work).
# It runs as its own system user bloch-l2-mainnet-shadow (created here, in the read group: review r10 decision 4),
# never as the settler user, which holds the DA fee key and the prover SSH key.
#
#   install-shadow.sh --verify OUT_DIR     (no root: pin + build.json checks only, changes nothing)
#   install-shadow.sh --print-l1-rpcs      (no root: prints configured L1 RPCs)
#   install-shadow.sh --print-config [SETTLER_CONFIG]   (no root: the config this install writes, changes nothing)
#   install-shadow.sh OUT_DIR [--start]
#   install-shadow.sh --rollback
#
# FORK CANDIDATE (December program swap; native L2_NEXT_PROGRAM_EPOCH and L2_PROGRAM_ROLLBACK_EPOCH inert in this
# tree). OUT_DIR is build-release.sh's OUT of the fork-candidate L2 build against native f12b4113 (agent 143's
# candidate v2, settlement-recovery lock ab7b3a09...): bloch-l2-produce-dev 425d4fe8... (the --rule-set producer),
# the schedule-aware sequencer_mainnet.py pinned below, SHA256SUMS and build.json. CANDIDATE values against an
# unreleased native: they move with the final December build, and the deposit-only launch kit keeps its own
# install-shadow.sh (v2.1 pins). The producer RUNS the native transition, so a shadow built against another
# native diverges at that native's first fork.
# What it does: verifies both files against the pins below and build.json against this build (the content
# pins of both files, native, lock, compiled L1 gates, both L2 program gates present), requires the settler's
# producer (if configured) to be the same build, creates /var/lib/bloch-l2-mainnet-shadow/{work,tmp} owned by the shadow user,
# writes the config (next_elf_keccak and fallback_elf_keccak, so the shadow follows the program swap and its
# rollback; the settler's program_switch_lead_seconds, so both use one window; refused if the settler's
# next or fallback l2-config names another ELF), creates the shadow L2 database at the pinned mainnet genesis (refuses any other
# hash), runs a read-only `check` against the configured L1 RPCs and installs the unit. It starts the
# unit only with --start. The shadow never signs, proves or submits and never opens the settler's
# database: starting it sends nothing to Bloch L1. It reads getl2settlement only.
#
# After an accepted settlement (a reinstall after --rollback, or the repair after l2_reorg_recover.py --apply:
# --rollback, then install again) the shadow database is not created at genesis: it is rebuilt from L1 with
# `produce reconstruct --l1-follower` over the local follower's verified blocks, so its head is the accepted
# settlement and `check` passes. Needs the local follower (P3) at or past that settlement.
#
# Rollback: stops and disables the unit, removes the unit file, and MOVES (never deletes)
# /opt/bloch/l2-mainnet-shadow, its config and /var/lib/bloch-l2-mainnet-shadow aside with a
# timestamp. The settler is not touched; nothing on L1 depends on the shadow.
set -euo pipefail
# Fork candidate v2 out/ (agent 143, reproduced on 136 and 45.77): produce-dev 425d4fe8... The launch kit's v2.1
# pins (produce e3f1a290..., sequencer 15daa26f...) have no --rule-set and no schedule: never use them for the fork.
PRODUCE_SHA256=425d4fe84cde5833070dcd05f7b18edcf912fdd214a478aa5bf9c5241144cc78
# deployment/mainnet/sequencer_mainnet.py of this tree (schedule-aware shadow, agent 218).
SEQUENCER_SHA256=e148306b18944a0d798e1de3c376d97d1fec1770540e641250712c3f29ec1915
NATIVE_COMMIT=a2fc3d0fb140e1011196bee78ed0057acba072c1
NATIVE_LOCK_SHA256=ab7b3a0901f142d5e2a3905c68cf97eb69eb5cc968407621e55f21f14668cafa
# The programs that run the next rules: native PROGRAM_NEXT (forced sparse guest bc35e838...) and PROGRAM_FALLBACK
# (forced complete guest 7fd7f3c0...), i.e. settler_v3.py MAINNET_NEXT_SPARSE and MAINNET_FALLBACK. CANDIDATE: they move with
# the fee-sweep recipient (TBD-owner) and the final ELFs.
NEXT_ELF_KECCAK=1f744da8d3e0302cd39152e24e91071d7f0cfec7639245566a471cd6083a6b18
FALLBACK_ELF_KECCAK=d95185a60668b0d4e1da49be00d85b9c550b412f13c5155be454e72889f90bf1
SETTLER_CONFIG=/etc/bloch-l2-mainnet-settler/config.json
UNIT=bloch-l2-mainnet-shadow.service
OPT=/opt/bloch/l2-mainnet-shadow
ETC=/etc/bloch-l2-mainnet-shadow
VAR=/var/lib/bloch-l2-mainnet-shadow
USER_=bloch-l2-mainnet-shadow
READ_GROUP=bloch-l2-mainnet-l2read
SETTLER_WORK=/var/lib/bloch-l2-mainnet-settler/work
FOLLOWER_NATIVE=/var/lib/bloch-l2-mainnet-follower/native
DOMAIN=1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733
GENESIS_TIME=1786656679
TIMESTAMP_RULE=1:1786656679:30000
HERE=$(cd "$(dirname "$0")" && pwd)

# L1 RPCs are configuration, not code. Source, in order: $L1_RPC_URLS (URLs separated by spaces or
# commas), else "rpc_urls" of the settler config, so the shadow reads the same L1 view as the settler.
# The rule is the settler installer's (install-settler-mainnet.py l1_rpc_urls): http(s)://HOST:PORT, at
# least 3, on distinct hosts (one failure domain each; a host named twice, with another port or a
# trailing slash, is one host). Prints them space-separated. The unit ships with IPAddressAllow=localhost
# and the install writes the hosts' addresses into a drop-in (as the follower and attestor installers do).
resolve_l1_rpcs() {
  python3 -I - "$SETTLER_CONFIG" "${L1_RPC_URLS:-}" <<'PY'
import json, os, re, sys, urllib.parse
settler_config, env = sys.argv[1:]
if env.strip():
    urls, source = [u for u in re.split(r'[\s,]+', env.strip()) if u], 'L1_RPC_URLS'
elif os.path.exists(settler_config):
    urls, source = list(json.load(open(settler_config)).get('rpc_urls') or []), settler_config
else:
    sys.exit(f'no L1 RPCs: set L1_RPC_URLS or install the settler first ({settler_config} has rpc_urls)')
seen, hosts, errors = [], [], []
for url in urls:
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError:
        parts, port = None, None
    if not (parts and parts.scheme in ('http', 'https') and parts.hostname and port and '@' not in parts.netloc
            and parts.path in ('', '/') and not parts.query and not parts.fragment
            and re.fullmatch(r'[A-Za-z0-9.-]+', parts.hostname)):
        errors.append(f'{url}: not an http(s)://HOST:PORT URL')
        continue
    host = parts.hostname.lower().rstrip('.')
    if host in hosts:
        errors.append(f'{url}: host {host} is named twice (the L1 RPCs must be on distinct hosts)')
        continue
    hosts.append(host)
    seen.append(url)
if len(seen) < 3:
    errors.append(f'{len(seen)} L1 RPCs on distinct hosts from {source}; need at least 3 (quorum 2 of 3)')
if errors:
    sys.exit('L1 RPC configuration refused: ' + '; '.join(errors))
print(' '.join(seen))
PY
}

# The IPv4 addresses of the L1 RPC hosts, for the unit's IPAddressAllow drop-in (the unit denies every other
# address). A name is resolved now, and EVERY address it has is allowed (a name with several A records answers
# from any of them; review R308-2P-12). If its addresses change, run the install again after --rollback.
l1_rpc_addresses() {
  local url host ips ip out=
  for url in "$@"; do
    host=$(python3 -I -c 'import sys, urllib.parse; print(urllib.parse.urlsplit(sys.argv[1]).hostname)' "$url")
    ips=$({ getent ahostsv4 "$host" || true; } | awk '!seen[$1]++ {print $1}')
    [ -n "$ips" ] || { echo "cannot resolve the L1 RPC host $host" >&2; return 1; }
    for ip in $ips; do
      case " $out " in *" $ip "*) echo "L1 RPC hosts resolve to the same address $ip: they must be distinct hosts" >&2; return 1;; esac
    done
    out="$out $(echo $ips)"
  done
  echo "${out# }"
}

# Prints the accepted commitment when a strict majority of the L1 RPCs report the same accepted settlement,
# "none" when a quorum reports none, and fails otherwise.
accepted_number() {
  python3 -I - "$@" <<'PY'
import collections, json, sys, urllib.request
views = []
for url in sys.argv[1:]:
    try:
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'getl2settlement', 'params': []}).encode()
        reply = json.load(urllib.request.urlopen(urllib.request.Request(url, body, {'content-type': 'application/json'}), timeout=15))
        accepted = reply['result'].get('accepted')
        views.append(json.dumps(accepted, sort_keys=True))
    except Exception as why:
        print(f'{url}: {why}', file=sys.stderr)
view, count = collections.Counter(views).most_common(1)[0] if views else (None, 0)
need = len(sys.argv[1:]) // 2 + 1
if count < need:
    sys.exit(f'no quorum of {need} nodes agrees on the accepted settlement')
accepted = json.loads(view)
print('none' if accepted is None else 'commitment ' + str(accepted.get('commitment')))
PY
}

verify_out() {
  local out=$1
  echo "$PRODUCE_SHA256  $out/bloch-l2-produce-dev" | sha256sum -c -
  echo "$SEQUENCER_SHA256  $out/sequencer_mainnet.py" | sha256sum -c -
  (cd "$out" && sha256sum -c --strict --ignore-missing SHA256SUMS)
  [ -f "$out/build.json" ] || { echo "missing $out/build.json (not a build-release.sh OUT)"; return 1; }
  python3 -I - "$out/build.json" "$NATIVE_COMMIT" "$NATIVE_LOCK_SHA256" "$PRODUCE_SHA256" "$SEQUENCER_SHA256" <<'PY'
import json, sys
path, native, lock, produce, sequencer = sys.argv[1:]
b = json.load(open(path))
gates = b.get('l1_activation_epochs') or {}
want = {'HF1_CLAIM_FINALITY_EPOCH': 7180, 'HF1_FROZEN_FINALITY_SET_EPOCH': 7180, 'HF1_OWN_TARGET_VOTES_EPOCH': 7186,
        'HF2_SLASHING_V2_EPOCH': 7270, 'HF2_GROWTH_CAP_EPOCH': 7270, 'SIG_CANONICAL_ACTIVATION_EPOCH': 7270,
        'HF3_KES_EPOCH': 7360, 'HF3_SLH_SUITE_EPOCH': 7360, 'HF3_PQ_MIGRATION_EPOCH': 7360,
        'HF3_KES_ENFORCE_EPOCH': 8620}
errors = []
if b.get('chain_id') != 700770: errors.append(f"chain_id {b.get('chain_id')}")
# The L2 commit cannot be pinned in the tree it names: the content pins of the two installed files stand for it.
if b.get('l2_tracked_changes') != 0: errors.append('the build had tracked changes')
if (b.get('sha256') or {}).get('sequencer_mainnet.py') != sequencer: errors.append('build.json sequencer_mainnet.py sha differs')
if not str(b.get('native', '')).startswith(native): errors.append(f"native {b.get('native')} != {native}")
if b.get('settlement_recovery_lock_sha256') != lock: errors.append('settlement-recovery lock is not the pinned lock')
if (b.get('sha256') or {}).get('bloch-l2-produce-dev') != produce: errors.append('build.json produce-dev sha differs')
if (b.get('l2_genesis') or {}).get('hash') != '632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468':
    errors.append('L2 genesis is not the pin')
errors += [f'{k} compiled {gates.get(k)} != L1 release {v}' for k, v in want.items() if gates.get(k) != v]
program = {k: gates.get(k) for k in ('L2_NEXT_PROGRAM_EPOCH', 'L2_PROGRAM_ROLLBACK_EPOCH')}
errors += [f'{k} missing from build.json (not a program-swap build)' for k, v in program.items() if v is None]
if errors:
    sys.exit('build.json is not the pinned build: ' + '; '.join(errors))
print(f"build.json OK: L2 {str(b.get('l2_commit'))[:8]}, native {native[:8]}, HF1 7180/7186, HF2 7270, HF3 7360, "
      f"KES enforce 8620, swap {program['L2_NEXT_PROGRAM_EPOCH']}, rollback {program['L2_PROGRAM_ROLLBACK_EPOCH']}")
PY
}

# The shadow config. The rule set follows the program swap and its rollback (next_elf_keccak, fallback_elf_keccak);
# the window is the settler's, so both select the same program at the same L1 slot. Refuses a settler whose next
# or fallback program names another ELF than these pins (one kit for both).
shadow_config() {
  local rpcs
  rpcs=$(resolve_l1_rpcs) || return 1
  python3 -I - "$1" "$OPT" "$VAR" "$SETTLER_WORK" "$PRODUCE_SHA256" "$NEXT_ELF_KECCAK" "$FALLBACK_ELF_KECCAK" "$rpcs" <<'PY'
import json, sys
from pathlib import Path
settler_config, opt, var, settler_work, produce, nxt, fallback, rpcs = sys.argv[1:]
settler = json.loads(Path(settler_config).read_text()) if Path(settler_config).is_file() else {}
for key, want in (('next_program', nxt), ('fallback_program', fallback)):
    if settler.get(key):
        elf = Path(settler[key]['l2_config']).read_bytes()[64:96].hex()  # domain, configuration, then the ELF Keccak
        if elf != want:
            sys.exit(f"the settler's {key} proves ELF {elf}, this shadow follows {want}: install both from one kit")
config = {
    'produce': f'{opt}/bloch-l2-produce-dev', 'produce_sha256': produce,
    'l2_db': f'{var}/canonical', 'workdir': f'{var}/work',
    'rpc_urls': rpcs.split(),
    'rpc_quorum': len(rpcs.split()) // 2 + 1, 'poll_seconds': 15, 'settler_workdir': settler_work,
    'next_elf_keccak': nxt, 'fallback_elf_keccak': fallback,
    'program_switch_lead_seconds': settler.get('program_switch_lead_seconds', 1800),
    'slots_per_epoch': settler.get('slots_per_epoch', 32),
}
print(json.dumps(config, indent=2))
PY
}

if [ "${1:-}" = "--print-config" ]; then
  shadow_config "${2:-$SETTLER_CONFIG}"
  exit 0
fi

if [ "${1:-}" = "--verify" ]; then
  verify_out "$(cd "${2:?usage: install-shadow.sh --verify OUT_DIR}" && pwd)"
  echo "verify OK (nothing installed)"
  exit 0
fi

if [ "${1:-}" = "--print-l1-rpcs" ]; then
  resolve_l1_rpcs
  exit 0
fi

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }

if [ "${1:-}" = "--rollback" ]; then
  TS=$(date -u +%Y%m%dT%H%M%SZ)
  systemctl disable --now "$UNIT" 2>/dev/null || true
  rm -rf "/etc/systemd/system/$UNIT" "/etc/systemd/system/$UNIT.d"
  systemctl daemon-reload
  [ -d "$OPT" ] && mv "$OPT" "$OPT.rollback-$TS"
  [ -d "$ETC" ] && mv "$ETC" "$ETC.rollback-$TS"
  [ -d "$VAR" ] && mv "$VAR" "$VAR.rollback-$TS"
  echo "rolled back at $TS (data kept as *.rollback-$TS; settler untouched)"
  exit 0
fi

OUT=$(cd "${1:?usage: install-shadow.sh OUT_DIR [--start] | --rollback}" && pwd)
START=${2:-}
[ -z "$START" ] || [ "$START" = "--start" ] || { echo "unknown option $START"; exit 1; }
verify_out "$OUT"
if [ -f "$SETTLER_CONFIG" ]; then
  SETTLER_PRODUCE=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1])).get("produce",""))' "$SETTLER_CONFIG")
  if [ -n "$SETTLER_PRODUCE" ]; then
    echo "$PRODUCE_SHA256  $SETTLER_PRODUCE" | sha256sum -c - || {
      echo "the settler's producer $SETTLER_PRODUCE is not this build: upgrade the settler first"; exit 1; }
  fi
fi
[ -f "$HERE/$UNIT" ] || { echo "missing $HERE/$UNIT"; exit 1; }
if systemctl is-active --quiet "$UNIT"; then echo "$UNIT is running; roll back first"; exit 1; fi
[ ! -e "$VAR/canonical" ] || { echo "$VAR/canonical exists; roll back first (it is moved aside, not deleted)"; exit 1; }

getent group "$READ_GROUP" >/dev/null || { echo "group $READ_GROUP missing: run install-settler-mainnet.py prepare first"; exit 1; }
[ -d "$SETTLER_WORK" ] || { echo "$SETTLER_WORK missing: run install-settler-mainnet.py prepare first"; exit 1; }
id "$USER_" >/dev/null 2>&1 || useradd --system --no-create-home --home-dir "$VAR" --shell /usr/sbin/nologin --groups "$READ_GROUP" "$USER_"
runuser -u "$USER_" -- test -r "$SETTLER_WORK" -a -x "$SETTLER_WORK" || {
  echo "$USER_ cannot read $SETTLER_WORK through group $READ_GROUP (a prepare by an older installer?)"; exit 1; }
L1_RPCS=$(resolve_l1_rpcs) || { echo "unit NOT installed"; exit 1; }
read -r -a L1_RPC_LIST <<< "$L1_RPCS"
L1_RPCS_JSON=$(python3 -I -c 'import json, sys; print(json.dumps(sys.argv[1:]))' "${L1_RPC_LIST[@]}")
L1_ADDRESSES=$(l1_rpc_addresses "${L1_RPC_LIST[@]}") || { echo "unit NOT installed"; exit 1; }
echo "L1 RPCs: $L1_RPCS (addresses $L1_ADDRESSES)"
CONFIG_JSON=$(shadow_config "$SETTLER_CONFIG") || { echo "shadow config refused (see above); unit NOT installed"; exit 1; }
install -d -m 0755 "$OPT"
install -m 0755 "$OUT/bloch-l2-produce-dev" "$OPT/bloch-l2-produce-dev"
install -m 0644 "$OUT/sequencer_mainnet.py" "$OPT/sequencer_mainnet.py"
# The copies are what runs: check them, not only OUT (which may change after verify_out).
echo "$PRODUCE_SHA256  $OPT/bloch-l2-produce-dev" | sha256sum -c - && echo "$SEQUENCER_SHA256  $OPT/sequencer_mainnet.py" | sha256sum -c - \
  || { echo "the installed copies differ from the pins; nothing started (run --rollback)"; exit 1; }
install -d -m 0700 -o "$USER_" -g "$USER_" "$VAR" "$VAR/work" "$VAR/tmp"
install -d -m 0755 "$ETC"
printf '%s\n' "$CONFIG_JSON" > "$ETC/config.json"
chmod 0644 "$ETC/config.json"

S="runuser -u $USER_ -- env BLOCH_SEQUENCER_CONFIG=$ETC/config.json TMPDIR=$VAR/tmp /usr/bin/python3 -u $OPT/sequencer_mainnet.py"
ACCEPTED=$(accepted_number "${L1_RPC_LIST[@]}") || {
  echo "cannot read the accepted settlement; unit NOT installed"; exit 1; }
if [ "$ACCEPTED" = none ]; then
  $S init      # shadow database; refuses unless the genesis is 632e45ae...f468 / 2ad7e807...c05d
else
  echo "accepted settlement ($ACCEPTED): rebuilding the shadow database from L1 (follower $FOLLOWER_NATIVE)"
  [ -d "$FOLLOWER_NATIVE" ] || { echo "$FOLLOWER_NATIVE missing: install and sync the follower first (P3)"; exit 1; }
  runuser -u "$USER_" -- "$OPT/bloch-l2-produce-dev" reconstruct --target "$VAR/canonical" --l1-follower "$FOLLOWER_NATIVE" \
    --rules mainnet --domain "$DOMAIN" --genesis-time "$GENESIS_TIME" --timestamp-rule "$TIMESTAMP_RULE"
fi
$S check || { echo "read-only check failed (see above); unit NOT installed"; exit 1; }
install -m 0644 "$HERE/$UNIT" "/etc/systemd/system/$UNIT"
install -d -m 0755 "/etc/systemd/system/$UNIT.d"
printf '[Service]\nIPAddressAllow=%s\n' "$L1_ADDRESSES" > "/etc/systemd/system/$UNIT.d/l1-rpc.conf"
chmod 0644 "/etc/systemd/system/$UNIT.d/l1-rpc.conf"
systemctl daemon-reload
if [ "$START" = "--start" ]; then
  systemctl enable --now "$UNIT"
  sleep 20
  journalctl -u "$UNIT" -n 20 --no-pager
else
  echo "installed, not started: systemctl enable --now $UNIT"
fi
