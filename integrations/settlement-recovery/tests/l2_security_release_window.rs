// SPDX-License-Identifier: AGPL-3.0-or-later
//! Security review 2026-10-30. Claims are relayable by anyone, and a claim
//! above the window cap is admitted only as the window's first. So any small
//! matured claim landing first closes the exemption for that whole window
//! (2,880 blocks on mainnet). This test states the desired property and FAILS
//! against native 78d4921c.
//!
//! On the native line merged onto the released node the rule is one function
//! with a switch (`ReleaseWindow::admits(sats, exempt, after_earlier_claims)`):
//! the switch is on from the next L2 program (`L2_NEXT_PROGRAM_EPOCH`) or from
//! the release's own gate (`L2_RELEASE_EXEMPTION_ACTIVATION_EPOCH`), whichever
//! comes first. The property is stated with the switch on, and the rule of the
//! activated program (switch off) is shown beside it.

use bloch_pos_committee::l2_settlement::{
    mainnet::{BLCH, LIMITS},
    withdrawal::ReleaseWindow,
};

#[test]
fn a_small_first_claim_must_not_close_the_window_to_an_attested_large_claim() {
    let escrow = u128::from(1_000 * BLCH);
    let large = 200 * BLCH;
    let height = LIMITS.release_window_blocks * 10;

    let fresh = ReleaseWindow::default().at(&LIMITS, height, escrow);
    assert_eq!(fresh.cap, u128::from(100 * BLCH));
    assert!(fresh.admits(large, true, true), "control: the attested claim passes as the window's first");
    assert!(fresh.admits(large, true, false), "also under the activated program's rule");

    let mut after_small = fresh;
    after_small.released = 1_000_000;
    assert!(
        after_small.admits(large, true, true),
        "a 0.01 BLCH claim earlier in the window refuses the attested 200 BLCH claim"
    );
    assert!(!after_small.admits(large, true, false), "the activated program's rule: the exemption is the first claim's only");
}
