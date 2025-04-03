mod circuits;

use circuits::arithmetic_circuits::MultiplyChainCircuit;
use halo2_proofs::{
    circuit::Value,
    pasta::{Fp, EqAffine},
    plonk::{keygen_vk, keygen_pk, create_proof, verify_proof, SingleVerifier},
    poly::commitment::Params,
    transcript::{Blake2bWrite, Blake2bRead, Challenge255},
};

use rand_core::OsRng;

fn main() {
    let circuit = MultiplyChainCircuit{
        c1: Value::known(Fp::from(3)),
        c2: Value::known(Fp::from(2)),
        c3: Value::known(Fp::from(1)),
        c4: Value::known(Fp::from(7)),
        c5: Value::known(Fp::from(5)),
        c6: Value::known(Fp::from(4)),
        c7: Value::known(Fp::from(6)),
        c8: Value::known(Fp::from(48)),
        c9: Value::known(Fp::from(72)),
    };

    let k = 6;
    let params:Params<EqAffine> = Params::new(k);

    //let public_inputs: Vec<Vec<Fp>> = vec![vec![]];
    //let public_inputs_refs: Vec<&[Fp]> = public_inputs.iter().map(Vec::as_slice).collect();
    let public_inputs_refs: &[&[Fp]] = &[];

    let vk = keygen_vk(&params, &circuit).expect("vk generation fail");
    let pk = keygen_pk(&params, vk.clone(), &circuit).expect("pk generation fail");

    
    let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
    create_proof(
        &params,
        &pk,
        &[circuit.clone()],
        &[&public_inputs_refs],
        OsRng,
        &mut transcript,
    )
    .expect("proof generation fail");

    let proof = transcript.finalize();

    let strategy = SingleVerifier::new(&params);
    let mut verifier_transcript = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(&proof[..]);
    verify_proof::<_, _, _, _>(
        &params,
        &vk,
        strategy,
        &[&public_inputs_refs],
        &mut verifier_transcript,
    )
    .expect("proof verification fail");

    println!("Proof verified successfully!");
}
