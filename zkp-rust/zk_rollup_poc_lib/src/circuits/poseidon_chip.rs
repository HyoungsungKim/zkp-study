use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Instance, Error},
    pasta::Fp,
};
use halo2_gadgets::poseidon::{Hash, Pow5Chip, Pow5Config};
use halo2_gadgets::poseidon::primitives::{Spec, ConstantLength};
use std::convert::TryInto;

use crate::constants::POSEIDON_RATE;


#[derive(Debug, Clone)]
pub struct PoseidonConfig<const WIDTH: usize, const RATE: usize, const L: usize> {
    pub inputs: Vec<Column<Advice>>,
    pub pow5_config: Pow5Config<Fp, WIDTH, RATE>,
}

#[derive(Debug, Clone)]
pub struct PoseidonChip<
    S: Spec<Fp, WIDTH, RATE>,
    const WIDTH: usize,
    const RATE: usize,
    const L: usize,
> {
    pub config: PoseidonConfig<WIDTH, RATE, L>,
    _marker: std::marker::PhantomData<S>,
}

impl<S: Spec<Fp, WIDTH, RATE>, const WIDTH: usize, const RATE: usize, const L: usize> PoseidonChip<S, WIDTH, RATE, L>{
    pub fn construct(config: PoseidonConfig<WIDTH, RATE, L>) -> Self {
        Self {
            config,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> PoseidonConfig<WIDTH, RATE, L> {
        let state = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>();
        let partial_sbox = meta.advice_column();
        let rc_a = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let rc_b = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        for i in 0..WIDTH {
            meta.enable_equality(state[i]);
        }
        meta.enable_constant(rc_b[0]);

        let pow5_config = Pow5Chip::configure::<S>(
            meta,
            state.clone().try_into().unwrap(),
            partial_sbox.try_into().unwrap(),
            rc_a.try_into().unwrap(),
            rc_b.try_into().unwrap(),
        );

        PoseidonConfig {
            inputs: state.clone().try_into().unwrap(),
            pow5_config: pow5_config,
        }
    }

    pub fn hash(
        &self,
        mut layouter: impl Layouter<Fp>,
        words: &[AssignedCell<Fp, Fp>; POSEIDON_RATE],
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let pow5_chip = Pow5Chip::construct(self.config.pow5_config.clone());
        let word_cells = layouter.assign_region(
            || "load words",
            |mut region| -> Result<[AssignedCell<Fp, Fp>; L], Error> {
                let result = words
                    .iter()
                    .enumerate()
                    .map(|(i, word)| {
                        word.copy_advice(
                            || format!("word {}", i),
                            &mut region,
                            self.config.inputs[i],
                            0,
                        )
                    })
                    .collect::<Result<Vec<AssignedCell<Fp, Fp>>, Error>>();
                Ok(result?.try_into().unwrap())
            },
        )?;

        let hasher = Hash::<_, _, S, ConstantLength<L>, WIDTH, RATE>::init(
            pow5_chip,
            layouter.namespace(|| "hasher"),
        )?;
        hasher.hash(layouter.namespace(|| "hash"), word_cells)
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

    pub fn assign(
        &self,
        region: &mut Region<'_, Fp>,
        offset: usize,
        inputs: [Value<Fp>; L]
    ) -> Result<(), Error> {
        for (i, input) in inputs.iter().enumerate() {
            region.assign_advice(
                || format!("input {}", i),
                self.config.inputs[i],
                offset,
                || *input
            )?;
        }
        Ok(())
    }

    pub fn assign_constant(
        &self,
        layouter: &mut impl Layouter<Fp>,
        value: Fp,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        layouter.assign_region(
            || "assign constant",
            |mut region| {
                region.assign_advice(
                    || "constant value",
                    self.config.inputs[0], // 아무 컬럼
                    0,
                    || Value::known(value),
                )
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        pasta::Fp,
        plonk::{Circuit, ConstraintSystem, Error, Instance},
    };
    use halo2_gadgets::poseidon::primitives::{P128Pow5T3, ConstantLength, Hash as PoseidonPrimitiveHash};

    const WIDTH: usize = 3;
    const RATE: usize = 2;
    const L: usize = 2;

    #[derive(Default)]
    struct DummyPoseidonCircuit {
        inputs: [Value<Fp>; L],
    }

    impl Circuit<Fp> for DummyPoseidonCircuit {
        type Config = (PoseidonConfig<WIDTH, RATE, L>, Column<Instance>);
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                inputs: [Value::unknown(); L],
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let instance = meta.instance_column();
            meta.enable_equality(instance);
            let chip_config = PoseidonChip::<P128Pow5T3, WIDTH, RATE, L>::configure(meta);
            (chip_config, instance)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let (chip_config, instance) = config;
            let chip = PoseidonChip::<P128Pow5T3, WIDTH, RATE, L>::construct(chip_config);

            let message_cells: [AssignedCell<Fp, Fp>; L] = layouter.assign_region(
                || "load inputs",
                |mut region| {
                    self.inputs
                        .iter()
                        .enumerate()
                        .map(|(i, val)| {
                            region.assign_advice(
                                || format!("input {}", i),
                                chip.config.inputs[i],
                                0,
                                || *val,
                            )
                        })
                        .collect::<Result<Vec<_>, _>>()
                        .and_then(|cells| cells.try_into().map_err(|_| Error::Synthesis))
                },
            )?;

            let hash_result = chip.hash(layouter.namespace(|| "poseidon hash"), &message_cells)?;
            chip.expose_public(&mut layouter, &hash_result, instance, 0)?;
            Ok(())
        }
    }

    #[test]
    fn test_poseidon_hash_works() {
        let inputs_fp: [Fp; L] = [Fp::from(100), Fp::from(0)];
        let expected_hash = {
            let hasher = PoseidonPrimitiveHash::<_, P128Pow5T3, ConstantLength<L>, WIDTH, RATE>::init();
            hasher.hash(inputs_fp)
        };

        let circuit = DummyPoseidonCircuit {
            inputs: inputs_fp.map(Value::known),
        };

        let public_inputs = vec![vec![expected_hash]];
        let prover = MockProver::run(10, &circuit, public_inputs);
        match prover {
            Ok(prover) => {
                prover.assert_satisfied();
                println!("Test passed successfully!");
            }
            Err(e) => panic!("MockProver failed with error: {:?}", e),
        }
    }
}