use halo2_proofs::{
    circuit::{AssignedCell, Layouter},
    plonk::{Advice, Column, ConstraintSystem, Instance, Error, Fixed},
    pasta::Fp,
};
use halo2_gadgets::poseidon::{Pow5Chip, Pow5Config};
use halo2_gadgets::poseidon::primitives::P128Pow5T3;
use std::convert::TryInto;

use crate::constants::{POSEIDON_WIDTH, POSEIDON_RATE, POSEIDON_INPUTS};


#[derive(Clone, Debug)]
pub struct PoseidonChipConfig {
    pub poseidon_config: Pow5Config<Fp, POSEIDON_WIDTH, POSEIDON_RATE>,
    pub inputs: [Column<Advice>; POSEIDON_INPUTS],
    /*
    === Advice ===
    TransactionConfig = {sender_balance_before, receiver_balance_before, transaction_amount, sender_balance_after, receiver_balance_after}
    sender_address,
    receiver_address,    
     */
}

pub struct PoseidonChip {
    pub config: PoseidonChipConfig,
    pub _marker: std::marker::PhantomData<Fp>,
}

impl PoseidonChip {
    pub fn construct(config: PoseidonChipConfig) -> Self {
        Self {
            config,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn configure_poseidon(meta: &mut ConstraintSystem<Fp>) -> Pow5Config<Fp, POSEIDON_WIDTH, POSEIDON_RATE> {
        let state: [Column<Advice>; POSEIDON_WIDTH] =
        (0..POSEIDON_WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>().try_into().unwrap();

        let partial_sbox = meta.advice_column();

        let rc_a: [Column<Fixed>; POSEIDON_WIDTH] =
            (0..POSEIDON_WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>().try_into().unwrap();

        let rc_b: [Column<Fixed>; POSEIDON_WIDTH] =
            (0..POSEIDON_WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>().try_into().unwrap();

    
        Pow5Chip::<Fp, POSEIDON_WIDTH, POSEIDON_RATE>::configure::<P128Pow5T3>(
            meta,
            state,
            partial_sbox,
            rc_a,
            rc_b,
        )
    }

    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        inputs: [Column<Advice>; POSEIDON_INPUTS],
    ) -> PoseidonChipConfig {
        let poseidon_config = Self::configure_poseidon(meta);

        for col in inputs.clone().iter() {
            meta.enable_equality(*col);
        }

        PoseidonChipConfig {
            poseidon_config,
            inputs,
        }
    }

    pub fn hash(
        &self,
        mut layouter: impl Layouter<Fp>,
        inputs: [AssignedCell<Fp, Fp>; POSEIDON_INPUTS],
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let chip = Pow5Chip::<Fp, POSEIDON_WIDTH, POSEIDON_RATE>::construct(self.config.poseidon_config.clone());

        let hasher = halo2_gadgets::poseidon::Hash::<Fp, _, P128Pow5T3, _, POSEIDON_WIDTH, POSEIDON_RATE>
            ::init(chip, layouter.namespace(|| "poseidon"))?;
        
        hasher.hash(layouter.namespace(|| "poseidon hash"), inputs)
    }
    

    pub fn expose_public(
        &self,
        layouter: &mut impl Layouter<Fp>,
        hash: &AssignedCell<Fp, Fp>,
        instance: Column<Instance>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(hash.cell(), instance, row)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        pasta::Fp,
        plonk::{Circuit, ConstraintSystem, Error},
    };
    use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash as PoseidonPrimitiveHash};

    #[derive(Default)]
    struct DummyPoseidonCircuit {
        pub inputs: [Value<Fp>; POSEIDON_INPUTS],
    }

    impl Circuit<Fp> for DummyPoseidonCircuit {
        type Config = (PoseidonChipConfig, Column<Instance>);
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                inputs: [Value::unknown(); POSEIDON_INPUTS],
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let instance = meta.instance_column();
            meta.enable_equality(instance);

            let inputs: [Column<Advice>; POSEIDON_INPUTS] = core::array::from_fn(|_| meta.advice_column());
            let chip_config = PoseidonChip::configure(meta, inputs);

            (chip_config, instance)
        }

        fn synthesize(
            &self,
            (chip_config, instance): Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let chip = PoseidonChip::construct(chip_config.clone());

            let assigned_inputs: [AssignedCell<Fp, Fp>; POSEIDON_INPUTS] =
                layouter.assign_region(
                    || "load inputs",
                    |mut region| {
                        self.inputs
                            .iter()
                            .enumerate()
                            .map(|(i, val)| {
                                region.assign_advice(
                                    || format!("input {}", i),
                                    chip_config.inputs[i],
                                    0,
                                    || *val,
                                )
                            })
                            .collect::<Result<Vec<_>, _>>()
                            .and_then(|cells| Ok(cells.try_into().unwrap()))
                    },
                )?;

            let hash_result = chip.hash(layouter.namespace(|| "poseidon hash"), assigned_inputs)?;
            chip.expose_public(&mut layouter, &hash_result, instance, 0)?;

            Ok(())
        }
    }

    #[test]
    fn test_poseidon_hash_works() {
        let inputs_fp: [Fp; POSEIDON_INPUTS] = [
            Fp::from(100), // sender_balance_before
            Fp::from(0),   // receiver_balance_before
            Fp::from(50),  // transaction_amount
            Fp::from(50),  // sender_balance_after
            Fp::from(50),  // receiver_balance_after
            Fp::from(123), // sender_address
            Fp::from(456), // receiver_address
        ];

        // 예상되는 해시를 primitive로 계산
        let expected_hash = {
            let hasher = PoseidonPrimitiveHash::<_, P128Pow5T3, ConstantLength<POSEIDON_INPUTS>, POSEIDON_WIDTH, POSEIDON_RATE>::init();
            hasher.hash(inputs_fp)
        };

        let circuit = DummyPoseidonCircuit {
            inputs: inputs_fp.map(Value::known),
        };

        let public_inputs = vec![vec![expected_hash]];
        let prover = MockProver::run(9, &circuit, public_inputs).unwrap();
        prover.assert_satisfied();
    }
}
