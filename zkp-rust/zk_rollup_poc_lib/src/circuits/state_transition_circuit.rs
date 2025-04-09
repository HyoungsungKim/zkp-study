use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
    pasta::Fp,
};
use halo2_gadgets::poseidon::primitives::P128Pow5T3;

use crate::constants::{POSEIDON_RATE, POSEIDON_WIDTH, POSEIDON_INPUTS};
use crate::circuits::poseidon_chip::{PoseidonConfig, PoseidonChip};



#[derive(Clone)]
pub struct StateTransitionConfig {
    pub previous_block_hash_instance: Column<Instance>,
    pub current_block_hash_instance: Column<Instance>,
    pub combined_block_hash_instance: Column<Instance>,
    
    pub previous_block_hash_advice: Column<Advice>,
    pub current_block_hash_advice: Column<Advice>,
}

#[derive(Default, Clone)]
pub struct StateTransitionCircuit {
    pub previous_block_hash: Value<Fp>,
    pub current_block_hash: Value<Fp>,    
}

impl Circuit<Fp> for StateTransitionCircuit {
    type Config = (StateTransitionConfig, PoseidonConfig<POSEIDON_WIDTH, POSEIDON_RATE, POSEIDON_INPUTS>);
    type FloorPlanner = halo2_proofs::circuit::SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let previous_block_hash_instance = meta.instance_column();
        let current_block_hash_instance = meta.instance_column();
        let combined_block_hash_instance = meta.instance_column();
        meta.enable_equality(previous_block_hash_instance);
        meta.enable_equality(current_block_hash_instance);
        meta.enable_equality(combined_block_hash_instance);

        let previous_block_hash_advice = meta.advice_column();
        let current_block_hash_advice = meta.advice_column();

        meta.enable_equality(previous_block_hash_advice);
        meta.enable_equality(current_block_hash_advice);

        let poseidon_config = PoseidonChip::<P128Pow5T3, POSEIDON_WIDTH, POSEIDON_RATE, POSEIDON_INPUTS>::configure(meta);
        (
            StateTransitionConfig{
                previous_block_hash_instance,
                current_block_hash_instance,
                combined_block_hash_instance,

                previous_block_hash_advice,
                current_block_hash_advice,
            },
            poseidon_config
        )
    }


    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let poseidon_chip = PoseidonChip::<P128Pow5T3, POSEIDON_WIDTH, POSEIDON_RATE, POSEIDON_INPUTS>::construct(config.1);
        let previous_block_hash_cell = layouter.assign_region(
            || "assign instance",
            |mut region| {
                let cell  = region.assign_advice_from_instance(
                    || "previous block hash",
                    config.0.previous_block_hash_instance,
                    0,
                    config.0.previous_block_hash_advice,
                    0,
                )?;
                Ok(cell)
            }
        )?;

        let current_block_hash_cell = layouter.assign_region(
            || "assign instance",
            |mut region| {
                let cell  = region.assign_advice_from_instance(
                    || "current block hash",
                    config.0.current_block_hash_instance,
                    0,
                    config.0.current_block_hash_advice,
                    0,
                )?;
                Ok(cell)
            }
        )?;
        let inputs = [previous_block_hash_cell, current_block_hash_cell];
        let compressed_hash_cell = poseidon_chip.hash(
            layouter.namespace(|| "compress"), &inputs
        )?;
        layouter.constrain_instance(compressed_hash_cell.cell(), config.0.combined_block_hash_instance, 0)?;

        Ok(())
    }
}  

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{
        circuit::Value,
        dev::MockProver,
    };

    use crate::utils::poseidon_hash;

    #[test]
    fn test_state_transition_passes() {
        // 1. input 값 정의
        let prev = Fp::from(123);
        let curr = Fp::from(456);

        // 2. expected hash 계산 (off-circuit)
        let expected_hash = poseidon_hash(&[prev, curr]);

        // 3. circuit 생성
        let circuit = StateTransitionCircuit {
            previous_block_hash: Value::known(prev),
            current_block_hash: Value::known(curr),
        };

        // 4. public inputs: [prev, curr, expected_hash]
        let public_inputs = vec![vec![prev], vec![curr], vec![expected_hash]];

        // 5. prover
        let prover = MockProver::run(8, &circuit, public_inputs).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_state_transition_fails_with_wrong_root() {
        // 1. input 값 정의
        let prev = Fp::from(123);
        let curr = Fp::from(456);

        // 2. 잘못된 expected hash
        let wrong_hash = Fp::from(999);

        // 3. circuit 생성
        let circuit = StateTransitionCircuit {
            previous_block_hash: Value::known(prev),
            current_block_hash: Value::known(curr),
        };

        // 4. public inputs: [prev, curr, wrong_hash]
        let public_inputs = vec![vec![prev], vec![curr], vec![wrong_hash]];

        // 5. prover
        let prover = MockProver::run(8, &circuit, public_inputs).unwrap();
        assert!(prover.verify().is_err());
    }
}
