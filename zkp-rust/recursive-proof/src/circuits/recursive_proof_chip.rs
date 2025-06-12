use halo2_proofs::{
    circuit::{Value, Region},
    plonk::{Advice, Column, ConstraintSystem, Error, Instance, Selector},
    poly::Rotation,
    pasta::Fp,
};
use group::ff::PrimeField;

#[derive(Clone, Debug)]
pub struct RecursiveProofConfig {
    pub proof: Column<Instance>, 
    pub vk: Column<Instance>,
    pub input_a: Column<Advice>,
    pub input_b: Column<Advice>,
    pub s_recursive_proof: Selector,
}

pub struct RecursiveProofChip<F> {
    pub config: RecursiveProofConfig,
    pub _marker: std::marker::PhantomData<F>
}

impl <F: PrimeField> RecursiveProofChip<F> {
    pub fn construct(config: RecursiveProofConfig) -> Self {
        Self {
            config,
            _marker: std::marker::PhantomData
        }
    }
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
    ) -> RecursiveProofConfig {
        let proof = meta.instance_column();
        let vk = meta.instance_column();
        let input_a = meta.advice_column();
        let input_b = meta.advice_column();
        let s_recursive_proof = meta.selector();

        meta.create_gate("recursive proof gate", |meta| {
            let s_recursive_proof = meta.query_selector(s_recursive_proof);
            let input_a = meta.query_advice(input_a, Rotation::cur());
            let input_b = meta.query_advice(input_b, Rotation::cur());
            let proof = meta.query_instance(proof, Rotation::cur());
            let vk = meta.query_instance(vk, Rotation::cur());


        });
        RecursiveProofConfig {
            proof,
            vk, 
            input_a,
            input_b,
            s_recursive_proof,
        }   
    }
}