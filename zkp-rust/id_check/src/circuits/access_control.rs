use super::gadgets;
use gadgets::age_check::*;
use gadgets::gender_check::*;
use gadgets::nationality_check::*;

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Instance, Selector},
    poly::Rotation,
};

use group::ff::PrimeField;

#[derive(Default, Clone)]
struct AccessControlCircuit<F: PrimeField> {
    prover_age: Value<F>,           // for age check
    prover_gender: Value<F>,          // for gender check
    prover_country_code: Value<F>,     // for nationality check
}

#[derive(Clone)]
struct AccessControlCircuitConfig {
    age_check_config: gadgets::age_check::AgeCheckConfig,
    gender_check_config: gadgets::gender_check::GenderCheckConfig,
    nationality_check_config: gadgets::nationality_check::NationalityCheckConfig,

    age_check_flag_instance: Column<Instance>,
    required_age_instance: Column<Instance>,

    gender_check_flag_instance: Column<Instance>,
    required_gender_instance: Column<Instance>,

    nationality_check_flag_instance: Column<Instance>,
    required_country_codes_instance: Column<Instance>, 

    age_check_selector: Selector,
    gender_check_selector: Selector,
    nationality_check_selector: Selector, 
}

impl <F: PrimeField> Circuit<F> for AccessControlCircuit<F> {
    type Config = AccessControlCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let age_check_flag_instance = meta.instance_column();       // index 0
        let required_age_instance = meta.instance_column();         // index 1

        let gender_check_flag_instance = meta.instance_column();    // index 2
        let required_gender_instance = meta.instance_column();      // index 3

        let nationality_check_flag_instance = meta.instance_column(); // index 4
        let required_country_codes_instance = meta.instance_column(); // index 5

        meta.enable_equality(age_check_flag_instance);
        meta.enable_equality(required_age_instance);

        meta.enable_equality(gender_check_flag_instance);
        meta.enable_equality(required_gender_instance);

        meta.enable_equality(nationality_check_flag_instance);
        meta.enable_equality(required_country_codes_instance);

        // === Age Check Configuration ===
        let age = meta.advice_column();
        let age_check_flag_advice = meta.advice_column();
        let required_age_advice = meta.advice_column(); // To handle the addition of current timestamp and required age in advice column. 
        meta.enable_equality(age);
        meta.enable_equality(age_check_flag_advice);
        meta.enable_equality(required_age_advice);


        // === Gender Check Configuration ===
        let gender = meta.advice_column();
        let gender_check_flag_advice = meta.advice_column();
        let required_gender_advice = meta.advice_column(); 
        meta.enable_equality(gender);
        meta.enable_equality(gender_check_flag_advice);
        meta.enable_equality(required_gender_advice);


        // === Nationality Check Configuration ===
        let prover_country_code = meta.advice_column();
        let nationality_check_flag_advice = meta.advice_column();
        let required_country_codes_advice = meta.advice_column();

        meta.enable_equality(prover_country_code);
        meta.enable_equality(nationality_check_flag_advice);
        meta.enable_equality(required_country_codes_advice);

        let age_check_selector = meta.selector();
        let gender_check_selector = meta.selector();
        let nationality_check_selector = meta.selector();

        // === Configuration Structs for Each Check ===
        let age_check_config = AgeCheckConfig {
            age,
            age_check_flag_advice,
            age_check_flag_instance, // Assuming you have an instance column for age check flag,
            required_age_advice,
            required_age_instance, // Assuming you have an instance column for required age
            selector: age_check_selector,
        };

        let gender_check_config = GenderCheckConfig {
            gender,
            gender_check_flag_advice,
            gender_check_flag_instance, // Assuming you have a flag for gender check
            required_gender_advice,
            required_gender_instance,
            selector: gender_check_selector,
        };

        let nationality_check_config = NationalityCheckConfig {
            prover_country_code,
            nationality_check_flag_advice, // Assuming you have a flag for nationality check
            nationality_check_flag_instance,
            required_country_codes_advice,
            required_country_codes_instance,
            selector: nationality_check_selector,
        };  

        AccessControlCircuitConfig {
            age_check_config,
            gender_check_config,
            nationality_check_config,

            age_check_flag_instance,
            required_age_instance,
            
            gender_check_flag_instance,
            required_gender_instance,

            nationality_check_flag_instance,
            required_country_codes_instance,        

            age_check_selector,
            gender_check_selector,
            nationality_check_selector,     
        }

    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let prover_age = self.prover_age;
        let prover_gender = self.prover_gender;
        let prover_country_code = self.prover_country_code;
        
        let age_circuit = AgeCheckCircuit {
            age: prover_age,
        };

        age_circuit.synthesize(config.age_check_config.clone(), layouter.namespace(|| "age check"))?;

        let gender_circuit = GenderCheckCircuit {
            gender: prover_gender,
        };

        gender_circuit.synthesize(config.gender_check_config.clone(), layouter.namespace(|| "gender check"))?;

        let nationality_circuit = NationalityCheckCircuit {
            prover_country_code: prover_country_code,
        };

        nationality_circuit.synthesize(config.nationality_check_config.clone(), layouter.namespace(|| "nationality check"))?;

       Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{dev::MockProver, pasta::Fp};

    #[test]
    fn test_access_control_pass_all() {
        let circuit = AccessControlCircuit {
            prover_age: Value::known(Fp::from(20)),
            prover_gender: Value::known(Fp::from(1)),
            prover_country_code: Value::known(Fp::from(410)),
        };

        let public_inputs = vec![
            vec![Fp::from(1)],                  // age check flag
            vec![Fp::from(18)],                 // required age
            vec![Fp::from(1)],                  // gender check flag
            vec![Fp::from(1)],                  // required gender
            vec![Fp::from(1)],                  // nationality check flag
            vec![
                Fp::from(410),
                Fp::from(840),
                Fp::from(0),
                Fp::from(0),
                Fp::from(0),
            ],                                  // allowed nationalities
        ];

        let prover = MockProver::run(8, &circuit, public_inputs).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_access_control_fail_on_age() {
        let circuit = AccessControlCircuit {
            prover_age: Value::known(Fp::from(16)),
            prover_gender: Value::known(Fp::from(1)),
            prover_country_code: Value::known(Fp::from(410)),
        };

        let public_inputs = vec![
            vec![Fp::from(1)],                  // age check flag
            vec![Fp::from(18)],
            vec![Fp::from(1)],                  // gender check flag
            vec![Fp::from(1)],
            vec![Fp::from(1)],                  // nationality check flag
            vec![
                Fp::from(410),
                Fp::from(840),
                Fp::from(0),
                Fp::from(0),
                Fp::from(0),
            ],
        ];

        let prover = MockProver::run(8, &circuit, public_inputs).unwrap();
        if let Err(e) = prover.verify() {
            println!("Verification failed: {:?}", e);
        } else {
            println!("Verification unexpectedly succeeded");
        }
        assert!(prover.verify().is_err());
    }

    #[test]
    fn test_access_control_disabled_checks() {
        let circuit = AccessControlCircuit {
            prover_age: Value::known(Fp::from(1)),
            prover_gender: Value::known(Fp::from(0)),
            prover_country_code: Value::known(Fp::from(999)),
        };

        let public_inputs = vec![
            vec![Fp::from(0)],                  // age check flag
            vec![Fp::from(18)],
            vec![Fp::from(0)],                  // gender check flag
            vec![Fp::from(1)],
            vec![Fp::from(0)],                  // nationality check flag
            vec![
                Fp::from(410),
                Fp::from(840),
                Fp::from(0),
                Fp::from(0),
                Fp::from(0),
            ],
        ];

        let prover = MockProver::run(8, &circuit, public_inputs).unwrap();
        prover.assert_satisfied();
    }
}
