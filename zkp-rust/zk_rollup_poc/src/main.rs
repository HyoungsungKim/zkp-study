use halo2_proofs::{
    pasta::{Fp, EqAffine},
    dev::MockProver,
    plonk::{keygen_vk, keygen_pk, create_proof, verify_proof},
    poly::commitment::Params,
    transcript::{Blake2bWrite, Blake2bRead, Challenge255},
    circuit::Value,
};

use std::time::Instant;
use rand_core::OsRng;
use std::convert::TryInto;

use zk_rollup_poc_lib::circuits::zk_rollup_circuit::ZKRollupCircuit;
use zk_rollup_poc_lib::utils::build_merkle_tree;
use zk_rollup_poc_lib::constants::*; // Importing const

fn main() {
    // -----------------------------
    // 1. Prepare test transactions
    // -----------------------------
    let tx_aggregation = vec![
        [10, 5, 3, 7, 8, 0, 0],
        [10, 5, 3, 7, 8, 0, 0],
        [10, 5, 3, 7, 8, 0, 0],
        [10, 5, 3, 7, 8, 0, 0],
        [10, 5, 3, 7, 8, 0, 0],
        [10, 5, 3, 7, 8, 0, 0],
        [10, 5, 3, 7, 8, 0, 0],
        [10, 5, 3, 7, 8, 0, 0],
    ];

    let tx_fp_values_vec = tx_aggregation.clone()
    .iter()
    .map(|tx| tx.map(|v| Value::known(Fp::from(v)))
    ).collect::<Vec<[Value<Fp>; TX_FIELDS_COUNT]>>();

    let tx_fp_values: [[Value<Fp>; TX_FIELDS_COUNT]; TX_AGGREGATION_COUNT] = tx_fp_values_vec.try_into().unwrap();
    
    let tx_fp_vec = tx_aggregation.clone()
    .iter()
    .map(|tx| tx.map(|v| Fp::from(v)))
    .collect::<Vec<[Fp; TX_FIELDS_COUNT]>>();

    let tx_fp_hashes = tx_fp_vec.clone()
    .iter()
    .map(|tx| build_merkle_tree(tx).last().unwrap()[0])
    .collect::<Vec<_>>();

    let merkle_tree = build_merkle_tree(&tx_fp_hashes);
    let root_hash = merkle_tree.last().unwrap()[0];
    
    let zk_rollup_circuit = ZKRollupCircuit {
        tx_aggregations: tx_fp_values.clone(),
    };
    let public_inputs = vec![vec![root_hash]];
    let public_inputs_refs: Vec<&[Fp]> = public_inputs.iter().map(|v| &**v).collect();

    // Create a proof
    let k = 12;
    let params: Params<EqAffine> = Params::new(k);
    
    let prover = MockProver::run(k, &zk_rollup_circuit, public_inputs).unwrap();
    prover.assert_satisfied();
    println!("MockProver is satisfied!")

    /*
    println!("Start circuit setup...");
    let vk = keygen_vk(&params, &zk_rollup_circuit).expect("keygen_vk should not fail");
    println!("VK generated");
    
    let pk = keygen_pk(&params, vk, &zk_rollup_circuit).expect("keygen_pk should not fail");
    println!("PK generated");

    let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
    println!("Creating proof...");
    let _start = Instant::now();
    create_proof(
        &params,
        &pk,
        &[zk_rollup_circuit],
        &[&public_inputs_refs],
        OsRng,
        &mut transcript,
    )
    .expect("proof generation should not fail");
    println!("Proof generated in {:?}", _start.elapsed());
    let proof = transcript.finalize();

    // Verify the proof
    let mut verifier_transcript = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(&proof[..]);
    let strategy = halo2_proofs::plonk::SingleVerifier::new(&params);

    verify_proof(
        &params,
        pk.get_vk(),
        strategy,
        &[&public_inputs_refs],
        &mut verifier_transcript,
    )
    .expect("verification should not fail");
    println!("Proof verified successfully!");
     */
}