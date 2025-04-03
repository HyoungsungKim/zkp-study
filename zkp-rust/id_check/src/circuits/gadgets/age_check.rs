use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Instance, Selector},
    poly::Rotation
};
use halo2_gadgets::utilities::range_check;
use group::ff::PrimeField;

use crate::constants::MAX_AGE;

#[derive(Clone, Default)]
pub struct AgeCheckCircuit<F: PrimeField> {
    pub age: Value<F>,        // Birth timestamp
    //pub _required_age_advice: Value<F>,
   // pub required_age: Value<F>,    // Required age in seconds
}

#[derive(Clone)]
pub struct AgeCheckConfig {
    /*
        Advice: Columns used to store the values of the circuit's variables. Normally, these are private inputs.    
        Instance: Columns used to store public inputs and outputs. These are the values that will be verified by the circuit.    
     */
    pub age: Column<Advice>,
    pub age_check_flag_advice: Column<Advice>, // To handle the flag value in advice column.
    pub age_check_flag_instance: Column<Instance>,
    pub required_age_advice: Column<Advice>,  // To handle the required_age value in advice column. 
    pub required_age_instance: Column<Instance>,
    pub selector: Selector,
}

impl <F: PrimeField> Circuit<F> for AgeCheckCircuit<F> {
    type Config = AgeCheckConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let age = meta.advice_column();
        let age_check_flag_advice = meta.advice_column(); // To handle the flag value in advice column. 
        let age_check_flag_instance = meta.instance_column(); // To handle the flag value in advice column. 

        let required_age_advice = meta.advice_column(); // To handle the addition of current timestamp and required age in advice column. 
        let required_age_instance = meta.instance_column();
        let selector = meta.selector();

        meta.enable_equality(age);
        meta.enable_equality(age_check_flag_advice);
        meta.enable_equality(age_check_flag_instance);
        meta.enable_equality(required_age_advice);
        meta.enable_equality(required_age_instance);
        

        meta.create_gate("age >= required", |meta| {
            let sel = meta.query_selector(selector);
            let age = meta.query_advice(age, Rotation::cur());
            let age_check_flag_advice = meta.query_advice(age_check_flag_advice, Rotation::cur());
            let required_age_advice = meta.query_advice(required_age_advice, Rotation::cur());
            //let _required_age = meta.query_instance(required_age, Rotation::cur());

            let diff = age - required_age_advice;
            let adjusted = Expression::Constant(F::from(MAX_AGE as u64)) - diff;

            vec![sel * age_check_flag_advice * range_check(adjusted.clone(), MAX_AGE)]
            //vec![Expression::Constant(F::from(1)]
        });

        AgeCheckConfig{
            age,
            age_check_flag_advice,
            age_check_flag_instance,
            required_age_advice,
            required_age_instance,
            selector,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "age check gate",
            |mut region| {
                config.selector.enable(&mut region, 0)?;
                

                let age_cell = region.assign_advice(
                    || "age",
                    config.age,
                    0,
                    || self.age,
                )?;

                let flag_cell = region.assign_advice_from_instance(
                    || "load flag instance to advice",
                    config.age_check_flag_instance,
                    0,
                    config.age_check_flag_advice,
                    0,
                )?;

                let required_age_cell = region.assign_advice_from_instance(
                    || "load instance to advice",
                    config.required_age_instance,
                    0,
                    config.required_age_advice,
                    0,
                )?;

                // adjusted 값 계산
                let diff = age_cell.value().copied() - required_age_cell.value().copied();
                let adjusted = Value::known(F::from(MAX_AGE as u64)) - diff;

                // 디버깅 출력
                println!("⛏️ AgeCheckCircuit Debug Info:");
                println!("  ▶ age value               : {:?}", age_cell.value());
                println!("  ▶ age_check_flag value    : {:?}", flag_cell.value());
                println!("  ▶ required_age value      : {:?}", required_age_cell.value());
                println!("  ▶ diff                    : {:?}", diff);
                println!("  ▶ adjusted                : {:?}", adjusted);
                println!("  ▶ MAX_AGE                 : {}", MAX_AGE);
                Ok(())
            },
        )?;

        Ok(())
    }
}

#[test]
fn test_age_check_pass() {
    use halo2_proofs::{dev::MockProver, pasta::Fp};

    let age = Fp::from(20);
    let flag = Fp::from(1);
    let required = Fp::from(18);
   // let required_age_advice = required.clone();

    let circuit = AgeCheckCircuit {
        age: Value::known(age),
        //required_age_advice: Value::known(required_age_advice),
    };

    let public_inputs = vec![vec![flag], vec![required]];

    let prover = MockProver::run(4, &circuit, public_inputs).unwrap();
    prover.assert_satisfied();
}

#[test]
fn test_age_check_fail() {
    use halo2_proofs::{dev::MockProver, pasta::Fp};

    let age = Fp::from(16);
    let flag = Fp::from(1);
    let required = Fp::from(18);
   // let required_age_advice = required.clone();

    let circuit = AgeCheckCircuit {
        age: Value::known(age),
        //required_age_advice: Value::known(required_age_advice),
    };

    let public_inputs = vec![vec![flag], vec![required]];

    let prover = MockProver::run(8, &circuit, public_inputs).unwrap();
    assert!(prover.verify().is_err()); 
}
