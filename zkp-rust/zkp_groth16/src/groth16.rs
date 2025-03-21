use ark_circom::{CircomBuilder, CircomConfig};
use ark_std::rand::thread_rng;
use color_eyre::Result;

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::Groth16;

type GrothBn = Groth16<Bn254>;

pub async fn groth16_proof() -> Result<()> {
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
    let params = GrothBn::generate_random_parameters_with_reduction(circom, &mut rng)?;

    let circom = builder.build()?;
    let inputs = circom.get_public_inputs().unwrap();

    let proof = GrothBn::prove(&params, circom, &mut rng)?;
    println!("Proof: {:?}", proof);

    let pvk = GrothBn::process_vk(&params.vk).unwrap();
    let verified = GrothBn::verify_with_processed_vk(&pvk, &inputs, &proof)?;
    println!("Verification result: {}", verified);
    assert!(verified);

    Ok(())

    
}