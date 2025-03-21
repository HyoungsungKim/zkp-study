use ark_circom::{CircomBuilder, CircomConfig};
use ark_bn254::{Bn254, Fr};
use ark_poly_commit::kzg10::{KZG10, UniversalParams};
use ark_std::rand::thread_rng;
use arf_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use ark_plonk::prelude::*;
use color_eyre::Result;

pub async fn KZG_plonk() -> Result<()> {
    let cfg = CircomConfig::<Fr>::new(
        "/app/zkp-rust/zkp_groth16/build/circuit_js/circuit.wasm",
        "/app/zkp-rust/zkp_groth16/build/circuit.r1cs"        
    )?;

  // 공개 입력 추가 (예: a=3, b=11에 맞게 조정)
    let mut builder = CircomBuilder::new(cfg);
    builder.push_input("c1", 3); // Circom의 입력 이름에 맞게 조정 필요
    builder.push_input("c2", 2);
    builder.push_input("c3", 1);
    builder.push_input("c4", 7);
    builder.push_input("c5", 5);
    builder.push_input("c6", 4);

    let circom = builder.setup();
    let mut rng = thread_rng();

    let max_degree = 100;
    let srs = KZG10::<Bn254>::setup(max_degree, &mut rng)?;
    println!("SRS generated with degree bound: {}", max_degree);
    println!("SRS size: {}", srs.powers_of_g.len());

    let circuit = circom.clone().into_plonk()?;
    println!("Plonk circuit constraints: {}", circuit.num_constraints());

    let mut plonk_setup = PlonkSetup::new(&srs);
    let params = plonk_setup.setup(&circuit, &mut rng)?;
    println!("Plonk parameters generated: {:?}", params);

    // 7. 증명 생성
    let circom = builder.build()?;
    let proof = Plonk::<Bn254>::prove(&params, &circuit, &circom.witness()?, &mut rng)?;
    println!("Plonk proof: {:?}", proof);

    // 8. 공개 입력 추출
    let public_inputs = circom.get_public_inputs().unwrap();
    println!("Public inputs: {:?}", public_inputs);

    // 9. 검증
    let verified = Plonk::<Bn254>::verify(&params, &public_inputs, &proof)?;
    println!("Verification result: {}", verified);
    assert!(verified);

    Ok(())
}