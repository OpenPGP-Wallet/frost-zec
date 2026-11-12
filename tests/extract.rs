//! The last mile of a spend, offline: a PCZT built for a FROST group, signed by
//! a real signing session, proved with the Ironwood circuit like the wallet
//! does, then extracted. The extractor verifies the proofs, every spend
//! authorization signature and the binding signature against the sighash, so a
//! pass means the transaction is valid in everything but its (made-up) anchor.
//!
//! Proving is slow without optimizations:
//!
//!     cargo test --release --test extract -- --ignored

mod common;

use common::*;
use frost_zec::cosigning::{self, CoordinatorSession, Member};
use frost_zec::{dkg, keys, pczt_io, signing};
use pczt::roles::prover::Prover;
use pczt::roles::tx_extractor::TransactionExtractor;
use rand10::rand_core::UnwrapErr;
use rand10::rngs::SysRng;
use zcash_protocol::consensus::{BranchId, NetworkType};

fn group() -> Vec<Member> {
    let (key_packages, public_key_package) = dkg::run(3, 2).unwrap();
    let ak = signing::group_ak(&public_key_package).unwrap();
    let fvk = keys::derive(&rand::random(), &ak).unwrap().fvk;
    key_packages
        .into_values()
        .map(|key_package| Member {
            key_package,
            public_key_package: public_key_package.clone(),
            fvk: fvk.clone(),
            network: NetworkType::Main,
        })
        .collect()
}

#[test]
#[ignore = "slow without --release: proves with the Ironwood circuit"]
fn a_frost_signed_pczt_proves_and_extracts_into_a_valid_transaction() {
    let members = group();
    let fvk = &members[0].fvk;
    let pczt = pczt_io::serialize(build(fvk, honest(fvk, text_memo("rent")))).unwrap();

    let (coordinating, request, _) =
        CoordinatorSession::request(&members[0], &pczt, &mut UnwrapErr(SysRng)).unwrap();
    let signed = coordinating
        .finish(
            &cosigning::review(&members[1], &request)
                .ok()
                .unwrap()
                .approve(),
        )
        .unwrap();

    // Without a proof, the extractor refuses: it really verifies.
    assert!(
        TransactionExtractor::new(signed.clone())
            .extract(UnwrapErr(SysRng))
            .is_err()
    );

    // Prove as the wallet does (core/src/zcash_frost.rs, prove).
    let branch = BranchId::try_from(*signed.global().consensus_branch_id()).unwrap();
    let prover = Prover::new(signed);
    assert!(prover.requires_ironwood_proof());
    let version = zcash_primitives::transaction::components::orchard::bundle_version_for_branch(
        branch,
        orchard::ValuePool::Orchard,
    )
    .unwrap();
    let key = orchard::circuit::ProvingKey::build(version.circuit_version());
    let proved = prover
        .create_ironwood_proof(UnwrapErr(SysRng), &key)
        .unwrap()
        .finish();

    let tx = TransactionExtractor::new(proved)
        .extract(UnwrapErr(SysRng))
        .expect("proofs, spend authorizations and binding signature all verify");
    assert!(tx.ironwood_bundle().is_some());
}
