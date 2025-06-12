// Poseidon-based Bloom filter nationality check circuit in Halo2

use halo2_proofs::{
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Selector, Expression},
    poly::Rotation,
};
use group::ff::PrimeField;

use crate::constants::MAX_COUNTRY_NUMBER;


#[derive(Debug, Clone)]
pub struct NationalityCheckConfig {
    pub prover_country_code: Column<Advice>,
    pub nationality_check_flag_advice: Column<Advice>,
    pub required_country_codes_advice: Column<Advice>,
    pub selector: Selector,
}
pub struct NationalityCheckChip<F: PrimeField> {
    pub config: NationalityCheckConfig,
    pub _marker: std::marker::PhantomData<F>,
}

impl<F: PrimeField> NationalityCheckChip<F> {
    pub fn construct(config: NationalityCheckConfig) -> Self {
        Self {
            config,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
    ) -> NationalityCheckConfig {
        let prover_country_code = meta.advice_column();
        let flag = meta.advice_column();
        let required = meta.advice_column();

        meta.enable_equality(prover_country_code);
        meta.enable_equality(flag);
        meta.enable_equality(required);

        let selector = meta.selector();

        meta.create_gate("nationality check", |meta| {
            let sel = meta.query_selector(selector);
            let prover_code = meta.query_advice(prover_country_code, Rotation::cur());
            let flag = meta.query_advice(flag, Rotation::cur());

            let mut product = Expression::Constant(F::ONE);
            for i in 0..MAX_COUNTRY_NUMBER {
                let code_i = meta.query_advice(required, Rotation(i as i32));
                product = product * (prover_code.clone() - code_i);
            }

            vec![sel * flag * product]
        });

        NationalityCheckConfig {
            prover_country_code,
            nationality_check_flag_advice: flag,
            required_country_codes_advice: required,
            selector,
        }
    }

    pub fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        prover_country_code: Value<F>,
        flag: Value<F>,
        required_countries: Vec<Value<F>>,
    ) -> Result<(), Error> {
        self.config.selector.enable(region, offset)?;
            region.assign_advice(
                || "prover_country_code",
                self.config.prover_country_code,
                0,
                || prover_country_code,
            )?;

            region.assign_advice(
                || "check flag",
                self.config.nationality_check_flag_advice,
                0,
                || flag,
            )?;

            for i in 0..MAX_COUNTRY_NUMBER {
                region.assign_advice(
                    || format!("required country {}", i),
                    self.config.required_country_codes_advice,
                    i,
                    || {
                        if i < required_countries.len() {
                            required_countries[i]
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
    use super::*; // chip 코드 가져오기
    use halo2_proofs::{dev::MockProver, pasta::Fp, circuit::{Layouter, Value, SimpleFloorPlanner}, plonk::{Circuit, ConstraintSystem, Error}};

    #[derive(Default)]
    struct DummyCircuit<F: PrimeField> {
        prover_country_code: Value<F>,
        flag: Value<F>,
        required: Vec<Value<F>>,
    }
    
    impl<F: PrimeField> Circuit<F> for DummyCircuit<F> {
        type Config = NationalityCheckConfig;
        type FloorPlanner = SimpleFloorPlanner;
    
        fn without_witnesses(&self) -> Self {
            Self::default()
        }
    
        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            NationalityCheckChip::configure(meta)
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
            let chip = NationalityCheckChip::construct(config);
            
            layouter.assign_region(
                || "age check",
                |mut region| {
                chip.assign(
                    &mut region,
                    0,
                    self.prover_country_code,
                    self.flag,
                    self.required.clone(),
                )
            })?;
            Ok(())
        }
    }
    
    #[test]
    fn test_nationality_check_chip() {
        let flag = Value::known(Fp::from(1));
        let prover = Value::known(Fp::from(410));
        let required = vec![
            Value::known(Fp::from(410)),
            Value::known(Fp::from(840)),
            Value::known(Fp::from(0)),
            Value::known(Fp::from(0)),
            Value::known(Fp::from(0)),
        ];
    
        let circuit = DummyCircuit::<Fp> {
            prover_country_code: prover,
            flag,
            required,
        };
    
        let prover = MockProver::run(8, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }
    
}
