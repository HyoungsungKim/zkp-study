use halo2_proofs::{
    pasta::{Fp, EqAffine},
    plonk::{keygen_vk, keygen_pk, create_proof, verify_proof},
    poly::commitment::Params,
    transcript::{Blake2bWrite, Blake2bRead, Challenge255},
    circuit::Value,
};

use std::time::Instant;
use rand_core::OsRng;

use id_check_on_chip_lib::circuits::access_control::{AccessControlCircuit, Input}; 

fn main() {
    let circuit = AccessControlCircuit {
        prover_age: Input::Present(Value::known(Fp::from(20))),
        prover_gender: Input::Present(Value::known(Fp::from(1))),
        prover_country_code: Input::Present(Value::known(Fp::from(410))),
    };

    let public_inputs: Vec<Vec<Fp>> = vec![
        vec![Fp::from(1)], // age flag
        vec![Fp::from(18)],
        vec![Fp::from(1)], // gender flag
        vec![Fp::from(1)],
        vec![Fp::from(1)], // nationality flag
        vec![
            Fp::from(410),
            Fp::from(840),
            Fp::from(0),
            Fp::from(0),
            Fp::from(0),
        ],
    ];

    let public_inputs_refs: Vec<&[Fp]> = public_inputs.iter().map(|v| &**v).collect();

    let k = 7;
    let params: Params<EqAffine> = Params::new(k);

    let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");

    let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);

    let start = Instant::now();
    create_proof(
        &params,
        &pk,
        &[circuit],
        &[&public_inputs_refs],
        OsRng,
        &mut transcript,
    )
    .expect("proof generation should not fail");
    let proof = transcript.finalize();
    println!("Proof generated in {:?}", start.elapsed());

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
    println!("Proof verified successfully in {:?}!", start.elapsed());


}
