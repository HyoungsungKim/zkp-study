use halo2_proofs::{
    circuit::{Value, Region},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation
};
use halo2_gadgets::utilities::range_check;
use group::ff::PrimeField;

use crate::constants::MAX_AGE;


#[derive(Clone, Debug)]
pub struct AgeCheckConfig {    
    pub age: Column<Advice>,
    pub age_check_flag_advice: Column<Advice>, // To handle the flag value in advice column.
    pub required_age_advice: Column<Advice>,  // To handle the required_age value in advice column. 
    pub selector: Selector,
}

pub struct AgeCheckChip<F: PrimeField> {
    pub config: AgeCheckConfig,        // Birth timestamp
    pub _marker: std::marker::PhantomData<F>,
}

impl <F: PrimeField> AgeCheckChip<F> {
    pub fn construct(config: AgeCheckConfig) -> Self {
        Self {
            config,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
    ) -> AgeCheckConfig  {
        let age = meta.advice_column();
        let age_check_flag_advice = meta.advice_column();
        let required_age_advice = meta.advice_column();  // To handle the required_age value in advice column.  // To handle the flag value in advice column. 

        let selector = meta.selector();

        meta.enable_equality(age);
        meta.enable_equality(age_check_flag_advice);
        meta.enable_equality(required_age_advice);
        

        meta.create_gate("age >= required", |meta| {
            let sel = meta.query_selector(selector);
            let age = meta.query_advice(age, Rotation::cur());
            let flag = meta.query_advice(age_check_flag_advice, Rotation::cur());
            let required = meta.query_advice(required_age_advice, Rotation::cur());
            //let _required_age = meta.query_instance(required_age, Rotation::cur());

            let diff = age - required;
            let adjusted = Expression::Constant(F::from(MAX_AGE as u64)) - diff;

            vec![sel * flag * range_check(adjusted.clone(), MAX_AGE)]
            //vec![Expression::Constant(F::from(1)]
        });

        AgeCheckConfig{
            age,
            age_check_flag_advice,
            required_age_advice,
            selector,
        }
    }
    pub fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        age: Value<F>,
        flag: Value<F>,
        required_age: Value<F>,
    ) -> Result<(), Error> {
        self.config.selector.enable(region, offset)?;
    
        region.assign_advice(|| "age", self.config.age, offset, || age)?;
        region.assign_advice(|| "flag", self.config.age_check_flag_advice, offset, || flag)?;
        region.assign_advice(|| "required_age", self.config.required_age_advice, offset, || required_age)?;
    
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*; // chip 코드 가져오기
    use halo2_proofs::{dev::MockProver, pasta::Fp, circuit::{Layouter, Value, SimpleFloorPlanner}, plonk::{Circuit, ConstraintSystem, Error}};

    struct DummyCircuit<F: PrimeField> {
        pub age: Value<F>,
        pub flag: Value<F>,
        pub required_age: Value<F>,
    }

    impl<F: PrimeField> Circuit<F> for DummyCircuit<F> {
        type Config = AgeCheckConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                age: Value::unknown(),
                flag: Value::unknown(),
                required_age: Value::unknown(),
            }
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            AgeCheckChip::configure(meta) // 또는 필요한 인자 넘겨주기
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
            let chip = AgeCheckChip::construct(config);

            layouter.assign_region(
                || "age check",
                |mut region| {
                chip.assign(
                    &mut region,
                    0,
                    self.age,
                    self.flag,
                    self.required_age,
                )
            })?;
            Ok(())
        }
    }

    #[test]
    fn test_age_check_pass() {
        let age = Fp::from(20);
        let flag = Fp::from(1);
        let required = Fp::from(18);

        let circuit = DummyCircuit {
            age: Value::known(age),
            flag: Value::known(flag),
            required_age: Value::known(required),
        };

        let public_inputs = vec![];

        let prover = MockProver::run(4, &circuit, public_inputs).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_age_check_fail() {
        use halo2_proofs::{dev::MockProver, pasta::Fp};

        let age = Fp::from(16);
        let flag = Fp::from(1);
        let required = Fp::from(18);

        let circuit = DummyCircuit {
            age: Value::known(age),
            flag: Value::known(flag),
            required_age: Value::known(required),
        };

        let public_inputs = vec![];

        let prover = MockProver::run(8, &circuit, public_inputs).unwrap();
        assert!(prover.verify().is_err()); 
    }

}
