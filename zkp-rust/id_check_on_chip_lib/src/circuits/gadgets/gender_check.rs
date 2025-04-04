use halo2_proofs::{
    circuit::{Value, Region},
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};
use group::ff::Field;

#[derive(Debug, Clone)]
pub struct GenderCheckConfig {
    pub gender: Column<Advice>,
    pub gender_check_flag_advice: Column<Advice>,
    pub required_gender_advice: Column<Advice>,
    pub selector: Selector,
}

pub struct GenderCheckChip<F: Field> {
    pub config: GenderCheckConfig,
    pub _marker: std::marker::PhantomData<F>,
}

impl <F: Field> GenderCheckChip<F> {
    pub fn construct(config: GenderCheckConfig) -> Self {
        Self{
            config,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        gender: Column<Advice>,
        gender_check_flag_advice: Column<Advice>,
        required_gender_advice: Column<Advice>,
    ) -> GenderCheckConfig {
        let selector = meta.selector();

        meta.enable_equality(gender);
        meta.enable_equality(gender_check_flag_advice);
        meta.enable_equality(required_gender_advice);

        meta.create_gate("gender check", |meta| {
            let sel = meta.query_selector(selector);
            let gender = meta.query_advice(gender, Rotation::cur());
            let flag = meta.query_advice(gender_check_flag_advice, Rotation::cur());
            let required = meta.query_advice(required_gender_advice, Rotation::cur());

            // When required is 0, the gate is always satisfied.
            vec![sel * flag * required.clone() * (gender.clone() - required.clone())]
        });

        GenderCheckConfig{
            gender,
            gender_check_flag_advice,
            required_gender_advice, 
            selector,
        }
    }

    pub fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        gender: Value<F>,
        flag: Value<F>,
        required_gender: Value<F>,
    ) -> Result<(), Error> {
        self.config.selector.enable(region, 0)?;
        region.assign_advice(|| "gender", self.config.gender, offset, || gender)?;
        region.assign_advice(|| "flag", self.config.gender_check_flag_advice, offset, || flag)?;               
        region.assign_advice(|| "required_gender", self.config.required_gender_advice, offset, || required_gender)?;
    
        Ok(())
    }
    /* 
    pub fn assign(
        &self,
        mut layouter: impl Layouter<F>,
        gender: Value<F>,
        flag: Value<F>,
        required_gender: Value<F>,
    ) -> Result<(), Error> {
        let config = &self.config;
        layouter.assign_region(
            || "gender check region",
            |mut region| {
                self.config.selector.enable(&mut region, 0)?;
                region.assign_advice(|| "gender", config.gender, 0, || gender)?;
                region.assign_advice(|| "flag", config.gender_check_flag_advice, 0, || flag)?;               
                region.assign_advice(|| "required_gender", config.required_gender_advice, 0, || required_gender)?;
                Ok(())
            }
        )
    }*/
}


#[cfg(test)]
mod tests {
    use super::*; // chip 코드 가져오기
    use halo2_proofs::{dev::MockProver, pasta::Fp, circuit::{Value, SimpleFloorPlanner}, plonk::{Circuit, ConstraintSystem, Error}};

    struct DummyCircuit<F: Field> {
        pub gender: Value<F>,
        pub gender_check_flag_advice: Value<F>,
        pub required_gender_advice: Value<F>,
    }

    impl<F: Field> Circuit<F> for DummyCircuit<F> {
        type Config = GenderCheckConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                gender: Value::unknown(),
                gender_check_flag_advice: Value::unknown(),
                required_gender_advice: Value::unknown(),
            }
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let gender  = meta.advice_column();
            let gender_check_flag_advice = meta.advice_column();
            let required_gender_check_advice = meta.advice_column();
            GenderCheckChip::configure(meta, gender, gender_check_flag_advice, required_gender_check_advice) // 또는 필요한 인자 넘겨주기
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl halo2_proofs::circuit::Layouter<F>) -> Result<(), Error> {
            let chip = GenderCheckChip::construct(config);

            layouter.assign_region(
                || "gender check",
                |mut region| {
                chip.assign(
                    &mut region,
                    0,
                    self.gender,
                    self.gender_check_flag_advice,
                    self.required_gender_advice,
                )
            })?;
            Ok(())

        }
    }

    
    #[test]
    fn test_age_check_pass_all() {
        let gender = Fp::from(1);
        let flag = Fp::from(1);
        let required = Fp::from(0);

        let circuit = DummyCircuit {
            gender: Value::known(gender),
            gender_check_flag_advice: Value::known(flag),
            required_gender_advice: Value::known(required),
        };

        let public_inputs = vec![];

        let prover = MockProver::run(4, &circuit, public_inputs).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_age_check_pass() {
        let gender = Fp::from(1);
        let flag = Fp::from(1);
        let required = Fp::from(1);

        let circuit = DummyCircuit {
            gender: Value::known(gender),
            gender_check_flag_advice: Value::known(flag),
            required_gender_advice: Value::known(required),
        };

        let public_inputs = vec![];

        let prover = MockProver::run(4, &circuit, public_inputs).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_age_check_fail() {
        let gender = Fp::from(1);
        let flag = Fp::from(1);
        let required = Fp::from(2);

        let circuit = DummyCircuit {
            gender: Value::known(gender),
            gender_check_flag_advice: Value::known(flag),
            required_gender_advice: Value::known(required),
        };

        let public_inputs = vec![];

        let prover = MockProver::run(4, &circuit, public_inputs).unwrap();
        assert!(prover.verify().is_err()); 
    }

}
