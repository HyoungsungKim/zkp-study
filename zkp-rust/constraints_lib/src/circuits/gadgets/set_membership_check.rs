use halo2_proofs::{
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Selector, Expression},
    poly::Rotation,
};
use group::ff::PrimeField;

use crate::constants::MAX_MEMBERSHIP_NUMBER; 

#[derive(Debug, Clone)]
pub struct SetMembershipConfig {
    pub input_value: Column<Advice>,
    pub flag: Column<Advice>,
    pub set_column: Column<Advice>,
    pub selector: Selector,
}

pub struct SetMembershipChip<F: PrimeField> {
    pub config: SetMembershipConfig,
    pub _marker: std::marker::PhantomData<F>,
}

impl<F: PrimeField> SetMembershipChip<F> {
    pub fn construct(config: SetMembershipConfig) -> Self {
        Self {
            config,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        input_value: Column<Advice>,
        flag: Column<Advice>,
        set_column: Column<Advice>,
    ) -> SetMembershipConfig {
        meta.enable_equality(input_value);
        meta.enable_equality(flag);
        meta.enable_equality(set_column);

        let selector = meta.selector();

        meta.create_gate("set membership check", |meta| {
            let sel = meta.query_selector(selector);
            let input = meta.query_advice(input_value, Rotation::cur());
            let flag = meta.query_advice(flag, Rotation::cur());

            let mut product = Expression::Constant(F::ONE);
            for i in 0..MAX_MEMBERSHIP_NUMBER {
                let set_i = meta.query_advice(set_column, Rotation(i as i32));
                product = product * (input.clone() - set_i);
            }

            vec![sel * flag * product]
        });

        SetMembershipConfig {
            input_value,
            flag,
            set_column,
            selector,
        }
    }

    pub fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        input_value: Value<F>,
        flag: Value<F>,
        set_values: Vec<Value<F>>,
    ) -> Result<(), Error> {
        let config = &self.config;

        config.selector.enable(region, offset)?;

        region.assign_advice(|| "input value", config.input_value, offset, || input_value)?;
        region.assign_advice(|| "flag", config.flag, offset, || flag)?;

        for i in 0..MAX_MEMBERSHIP_NUMBER {
            region.assign_advice(
                || format!("set[{}]", i),
                config.set_column,
                offset + i,
                || {
                    if i < set_values.len() {
                        set_values[i]
                    } else {
                        Value::known(F::ZERO)
                    }
                },
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        pasta::Fp,
        plonk::{Circuit, ConstraintSystem, Error},
    };

    #[derive(Default)]
    struct DummyCircuit<F: PrimeField> {
        input: Value<F>,
        flag: Value<F>,
        set: Vec<Value<F>>,
    }

    impl<F: PrimeField> Circuit<F> for DummyCircuit<F> {
        type Config = SetMembershipConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let input = meta.advice_column();
            let flag = meta.advice_column();
            let set = meta.advice_column();
            SetMembershipChip::configure(meta, input, flag, set)
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
            let chip = SetMembershipChip::construct(config);
            layouter.assign_region(
                || "membership check",
                |mut region| {
                    chip.assign(&mut region, 0, self.input, self.flag, self.set.clone())
                },
            )
        }
    }

    #[test]
    fn test_set_membership_pass() {
        let flag = Value::known(Fp::from(1));
        let input = Value::known(Fp::from(42));
        let set = vec![
            Value::known(Fp::from(10)),
            Value::known(Fp::from(42)),
            Value::known(Fp::from(100)),
        ];

        let circuit = DummyCircuit::<Fp> {
            input,
            flag,
            set,
        };

        let prover = MockProver::run(8, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_set_membership_fail() {
        let flag = Value::known(Fp::from(1));
        let input = Value::known(Fp::from(77));
        let set = vec![
            Value::known(Fp::from(10)),
            Value::known(Fp::from(42)),
            Value::known(Fp::from(100)),
        ];

        let circuit = DummyCircuit::<Fp> {
            input,
            flag,
            set,
        };

        let prover = MockProver::run(8, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err());
    }
}
