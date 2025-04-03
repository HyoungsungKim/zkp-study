use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector},
    poly::Rotation,
};
use group::ff::Field;

#[derive(Debug, Clone, Default)]
pub struct GenderCheckCircuit<F: Field> {
    pub gender: Value<F>,
}

#[derive(Debug, Clone)]
pub struct GenderCheckConfig {
    pub gender: Column<Advice>,

    pub gender_check_flag_advice: Column<Advice>,
    pub gender_check_flag_instance: Column<Instance>,

    pub required_gender_advice: Column<Advice>,
    pub required_gender_instance: Column<Instance>,
    pub selector: Selector,
}

impl <F: Field> Circuit<F> for GenderCheckCircuit<F> {
    type Config = GenderCheckConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let gender = meta.advice_column();
        let gender_check_flag_advice = meta.advice_column();
        let gender_check_flag_instance = meta.instance_column();
        let required_gender_advice = meta.advice_column();
        let required_gender_instance = meta.instance_column();
        let selector = meta.selector();

        meta.enable_equality(gender);
        meta.enable_equality(gender_check_flag_advice);
        meta.enable_equality(gender_check_flag_instance);
        meta.enable_equality(required_gender_advice);
        meta.enable_equality(required_gender_instance);

        meta.create_gate("gender check", |meta| {
            let sel = meta.query_selector(selector);
            let gender = meta.query_advice(gender, Rotation::cur());
            let gender_check_flag_advice = meta.query_advice(gender_check_flag_advice, Rotation::cur());
            let required_gender_advice = meta.query_advice(required_gender_advice, Rotation::cur());

            vec![sel * gender_check_flag_advice * (gender - required_gender_advice)]
        });
        

        GenderCheckConfig{
            gender,
            gender_check_flag_advice,
            gender_check_flag_instance,
            required_gender_advice,
            required_gender_instance,
            selector,
        }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_region(
            || "gender check",
            |mut region| {
                // Load the selector into the region.
                // Assign the gender value to the advice column.
                
                region.assign_advice(
                    || "gender",
                    config.gender,
                    0,
                    || self.gender,
                )?;

                region.assign_advice_from_instance(
                    || "load flag instance to advice",
                    config.gender_check_flag_instance,
                    0,
                    config.gender_check_flag_advice,
                    0, // offset in the advice column. If you have multiple values to assign, increment this.
                )?;
                
                region.assign_advice_from_instance(
                    || "load instance to advice",
                    config.required_gender_instance,
                    0,
                    config.required_gender_advice,
                    0
                )?;
                config.selector.enable(&mut region, 0)?;

                Ok(())
            }
        )?;
        Ok(())
    }
}

#[test]
fn test_gender_check_pass() {
    use halo2_proofs::{dev::MockProver, pasta::Fp};

    let gender = Fp::from(0);
    let flag = Fp::from(1); // Assuming 0 means pass, 1 means need to check
   // let gender_advice = gender.clone(); // If you need to use the gender value in another column
    let required_0 = Fp::from(0);
    let required_1 = Fp::from(1);
    let required_2 = Fp::from(2);
   // let required_age_advice = required.clone();

    let circuit = GenderCheckCircuit {
        gender: Value::known(gender),
    };

    let public_inputs_0 = vec![vec![flag], vec![required_0]];
    let public_inputs_1 = vec![vec![flag], vec![required_1]];
    let public_inputs_2 = vec![vec![flag], vec![required_2]];

    // Pass    
    let prover1 = MockProver::run(4, &circuit, public_inputs_0).unwrap();

    // Fail
    let prover2 = MockProver::run(4, &circuit, public_inputs_1).unwrap();
    let prover3 = MockProver::run(4, &circuit, public_inputs_2).unwrap();
    prover1.assert_satisfied();
    assert!(prover2.verify().is_err()); 
    assert!(prover3.verify().is_err()); 
}
