mod circuits;
use circuits::add_chip::{AddChip, AddConfig}; // Corrected the module path and struct names

use halo2_proofs::transcript;
use halo2_proofs::{
    pasta::{Fp, EqAffine},
    plonk::{keygen_vk, keygen_pk, create_proof, verify_proof, Circuit},
    poly::commitment::Params,
    transcript::{Blake2bWrite, Blake2bRead, Challenge255},
    circuit::Value,
};

fn main() {
    let a = 5;
    let b = 3;
    let sum = a.clone() + b.clone();
    
}
