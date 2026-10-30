#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Rehearsal wrapper around the UNMODIFIED `attestor_agent.py check|once` CLI (main()) of a --prefix install.

The installed key belongs to a THROWAWAY 3-of-5 set, so identity (set file, sealed key header, key-check,
partial) is enforced against the throwaway set hash, while the live RPC quorum (getl2settlement) must still
name the real consensus set 1c06adbb… and every other mainnet pin. Everything else (binary SHA-256 pins
including the follower, manifest pin, follower status, RPC quorum, rebuild-check) is the production code
path. KITDIR is the install's own /opt/bloch/l2-attestor, so the agent version under test is whatever
`install-attestor.sh` installed there. The passphrase is a simulated systemd credential (CREDENTIALS_DIRECTORY).

  rehearsal_check.py KITDIR CONFIG THROWAWAY_SET_HASH check|once [--dry-run]
"""
import sys
kit, config, throw, *args = sys.argv[1:]
sys.path.insert(0, kit)
import attestor_agent as a, attestor_lib as lib  # noqa: E402
m = lib.MAINNET
pins = lib.Pins(m.chain_id, m.network, m.genesis, throw, m.manifest_sha256, m.l2_genesis_hash,
                m.network_args, m.timestamp_rule, m.large_claim_sat)


class RehearsalAgent(a.Agent):
    def view(self):  # the live policy must still name the REAL set
        saved, self.pins = self.pins, lib.MAINNET
        try:
            return super().view()
        finally:
            self.pins = saved


a.PINS, a.Agent = pins, RehearsalAgent
sys.exit(a.main([*args[:1], '--config', config, *args[1:]]))
