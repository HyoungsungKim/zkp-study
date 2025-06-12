use super::gadgets;
use gadgets::age_check::*;
use gadgets::gender_check::*;
use gadgets::nationality_check::*;

use halo2_proofs::{
    circuit::{ Layouter, SimpleFloorPlanner, Value},
    plonk::{ Circuit, Column, ConstraintSystem, Error, Instance},
};

use group::ff::PrimeField;

use crate::constants::MAX_COUNTRY_NUMBER;
const DUMMY_VAL: i64 = -1;

#[derive(Clone)]
pub enum Input<F: PrimeField> {
    Present(Value<F>),
    Absent,
}

impl<F: PrimeField> Input<F> {
    pub fn resolve_or_dummy(&self, dummy:F) -> Value<F> {
        match self {
            Input::Present(value) => *value,
            Input::Absent => Value::known(dummy),
        }
    }
}

#[derive(Clone)]
pub struct AccessControlCircuit<F: PrimeField> {
    pub prover_age: Input<F>,           // for age check
    pub prover_gender: Input<F>,          // for gender check
    pub prover_country_code: Input<F>,     // for nationality check
}

impl<F: PrimeField> Default for AccessControlCircuit<F> {
    fn default() -> Self {
        Self {
            prover_age: Input::Absent,
            prover_gender: Input::Absent,
            prover_country_code: Input::Absent,
        }
    }
}

#[derive(Clone)]
pub struct AccessControlCircuitConfig {
    age_check_config: AgeCheckConfig,
    gender_check_config: GenderCheckConfig,
    nationality_check_config: NationalityCheckConfig,  // Add this line for nationality check config

    // === Instance ===
    age_check_flag_instance: Column<Instance>,
    required_age_instance: Column<Instance>,

    gender_check_flag_instance: Column<Instance>,
    required_gender_instance: Column<Instance>,

    nationality_check_flag_instance: Column<Instance>,
    required_country_codes_instance: Column<Instance>,  
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

        for col in [
            age_check_flag_instance,
            required_age_instance,
            gender_check_flag_instance,
            required_gender_instance,
            nationality_check_flag_instance,
            required_country_codes_instance,
        ] {
            meta.enable_equality(col);
        }

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

        // === Configuration Structs for Each Check ===
        let age_check_config =  AgeCheckChip::configure(meta);
        let gender_check_config =  GenderCheckChip::configure(meta);
        let nationality_check_config =   NationalityCheckChip::configure(meta);

        AccessControlCircuitConfig {
            age_check_config,
            gender_check_config,
            nationality_check_config,        

            // === Instances ===
            age_check_flag_instance,
            required_age_instance,
            
            gender_check_flag_instance,
            required_gender_instance,

            nationality_check_flag_instance,
            required_country_codes_instance,          
        }

    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let age_check_chip: AgeCheckChip<F> = AgeCheckChip::construct(config.age_check_config.clone());
        let gender_check_chip: GenderCheckChip<F>  = GenderCheckChip::construct(config.gender_check_config.clone());
        let nationality_check_chip: NationalityCheckChip<F>  = NationalityCheckChip::construct(config.nationality_check_config.clone());

        layouter.assign_region(
            || "age check region",
            |mut region| {
                // Public inputs from instance to advice
                let flag_cell = region.assign_advice_from_instance(
                    || "flag",
                    config.age_check_flag_instance,
                    0,
                    age_check_chip.config.age_check_flag_advice,
                    0,
                )?;
        
                let required_age_cell = region.assign_advice_from_instance(
                    || "required_age",
                    config.required_age_instance,
                    0,
                    age_check_chip.config.required_age_advice,
                    0,
                )?;
        
                // Private input
                let age_cell = region.assign_advice(
                    || "age",
                    age_check_chip.config.age,
                    0,
                    || self.prover_age.resolve_or_dummy(F::from(DUMMY_VAL as u64)),
                )?;
        
                // Call assign directly with region
                age_check_chip.assign(
                    &mut region,
                    0,
                    age_cell.value().copied(),
                    flag_cell.value().copied(),
                    required_age_cell.value().copied(),
                )?;
                Ok(())
            }
        )?;

        layouter.assign_region(
            || "gender check", 
           |mut region| {

            let gender_cell = region.assign_advice(
                || "gender",
                gender_check_chip.config.gender,
                0,
                || self.prover_gender.resolve_or_dummy(F::from(DUMMY_VAL as u64)),
            )?; 

            let flag_cell = region.assign_advice_from_instance(
                || "flag",
                config.gender_check_flag_instance,
                0,
                gender_check_chip.config.gender_check_flag_advice,
                0,
            )?;

            let required_cell = region.assign_advice_from_instance(
                || "required gender",
                config.required_gender_instance,
                0, 
                gender_check_chip.config.required_gender_advice,
                0,
            )?;

            gender_check_chip.assign(
                &mut region,
                0,
                gender_cell.value().copied(),
                flag_cell.value().copied(),
                required_cell.value().copied(),
            )?;
            Ok(())
         }
        )?;

        layouter.assign_region(
            || "nationality_check",
            |mut region| {
            let nationality_cell = region.assign_advice(
                || "nationality",
                nationality_check_chip.config.prover_country_code,
                0,
                || self.prover_country_code.resolve_or_dummy(F::from(DUMMY_VAL as u64)),
            )?; 

            let flag_cell = region.assign_advice_from_instance(
                || "flag",
                config.nationality_check_flag_instance,
                0,
                nationality_check_chip.config.nationality_check_flag_advice,
                0,
            )?;

            let mut required_values = vec![];
            for i in 0..MAX_COUNTRY_NUMBER {
                let cell = region.assign_advice_from_instance(
                    || format!("required_country_{}", i),
                    config.required_country_codes_instance,
                    i,
                    nationality_check_chip.config.required_country_codes_advice,
                    i,
                )?;
                required_values.push(cell.value().copied());
            }

            nationality_check_chip.assign(
                &mut region,
                0,
                nationality_cell.value().copied(),
                flag_cell.value().copied(),
                required_values,
            )?;
            Ok(())
        }
       )
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{dev::MockProver, pasta::Fp};
    use halo2_proofs::circuit::Value;

    fn run_test(
        age: u64,
        required_age: u64,
        age_flag: u64,
        gender: u64,
        required_gender: u64,
        gender_flag: u64,
        country_code: u64,
        allowed_countries: Vec<u64>,
        nationality_flag: u64,
        should_succeed: bool,
    ) {
        let circuit = AccessControlCircuit {
            prover_age: Input::Present(Value::known(Fp::from(age))),
            prover_gender: Input::Present(Value::known(Fp::from(gender))),
            prover_country_code: Input::Present(Value::known(Fp::from(country_code))),
        };

        let mut allowed_countries_fp = allowed_countries
            .into_iter()
            .map(Fp::from)
            .collect::<Vec<_>>();
        // Fill up to MAX_COUNTRY_NUMBER
        while allowed_countries_fp.len() < MAX_COUNTRY_NUMBER {
            allowed_countries_fp.push(Fp::zero());
        }

        let public_inputs = vec![
            vec![Fp::from(age_flag)],          // age check flag
            vec![Fp::from(required_age)],      // required age
            vec![Fp::from(gender_flag)],       // gender check flag
            vec![Fp::from(required_gender)],   // required gender
            vec![Fp::from(nationality_flag)],  // nationality check flag
            allowed_countries_fp,              // allowed nationalities
        ];

        let prover = MockProver::run(8, &circuit, public_inputs).unwrap();

        if should_succeed {
            prover.assert_satisfied();
        } else {
            assert!(prover.verify().is_err(), "Expected verification failure, but it passed.");
        }
    }

    #[test]
    fn test_all_pass() {
        run_test(
            25, 18, 1,   // age: 25, required: 18, flag: enabled
            1, 1, 1,     // gender: 1, required: 1, flag: enabled
            410, vec![410, 840], 1,  // country: 410, allowed list, flag: enabled
            true
        );
    }

    #[test]
    fn test_fail_on_age_only() {
        run_test(
            16, 18, 1,   // age too low
            1, 1, 1,     
            410, vec![410, 840], 1,
            false
        );
    }

    #[test]
    fn test_fail_on_gender_only() {
        run_test(
            20, 18, 1,   // age ok
            0, 1, 1,     // gender mismatch
            410, vec![410, 840], 1,
            false
        );
    }

    #[test]
    fn test_fail_on_nationality_only() {
        run_test(
            20, 18, 1,   // age ok
            1, 1, 1,     // gender ok
            999, vec![410, 840], 1,  // nationality not in list
            false
        );
    }

    #[test]
    fn test_disabled_checks_all_pass() {
        run_test(
            10, 100, 0,   // age check disabled
            0, 1, 0,      // gender check disabled
            999, vec![], 0, // nationality check disabled
            true
        );
    }

    #[test]
    fn test_mixed_flags() {
        run_test(
            30, 18, 1,   // age pass
            1, 1, 1,     // gender pass
            999, vec![123], 0, // nationality check disabled (invalid value doesn't matter)
            true
        );
    }

    #[test]
    fn test_absent_input_with_flag_off_should_pass() {
        let circuit = AccessControlCircuit {
            prover_age: Input::Absent,
            prover_gender: Input::Absent,
            prover_country_code: Input::Absent,
        };

        let mut allowed_countries_fp = vec![Fp::from(410)];
        while allowed_countries_fp.len() < MAX_COUNTRY_NUMBER {
            allowed_countries_fp.push(Fp::zero());
        }

        let public_inputs = vec![
            vec![Fp::from(0)],  // age check flag off
            vec![Fp::from(18)],
            vec![Fp::from(0)],  // gender check flag off
            vec![Fp::from(1)],
            vec![Fp::from(0)],  // nationality check flag off
            allowed_countries_fp,
        ];

        let prover = MockProver::run(8, &circuit, public_inputs).unwrap();
        prover.assert_satisfied();  // ✅ Pass expected
    }

    #[test]
    fn test_absent_input_with_flag_on_should_fail() {
        let circuit = AccessControlCircuit {
            prover_age: Input::Absent,
            prover_gender: Input::Absent,
            prover_country_code: Input::Absent,
        };

        let mut allowed_countries_fp = vec![Fp::from(410)];
        while allowed_countries_fp.len() < MAX_COUNTRY_NUMBER {
            allowed_countries_fp.push(Fp::zero());
        }

        let public_inputs = vec![
            vec![Fp::from(1)],  // age check flag ON
            vec![Fp::from(18)],
            vec![Fp::from(1)],  // gender check flag ON
            vec![Fp::from(1)],
            vec![Fp::from(1)],  // nationality check flag ON
            allowed_countries_fp,
        ];

        let prover = MockProver::run(8, &circuit, public_inputs).unwrap();
        assert!(
            prover.verify().is_err(),
            "Expected failure due to Absent inputs with flags ON"
        );
    }

    #[test]
    fn test_mixed_input_with_some_flags_off_should_pass() {
        let circuit = AccessControlCircuit {
            prover_age: Input::Present(Value::known(Fp::from(25))),
            prover_gender: Input::Absent,
            prover_country_code: Input::Absent,
        };

        let mut allowed_countries_fp = vec![Fp::from(410)];
        while allowed_countries_fp.len() < MAX_COUNTRY_NUMBER {
            allowed_countries_fp.push(Fp::zero());
        }

        let public_inputs = vec![
            vec![Fp::from(1)],  // age check ON
            vec![Fp::from(18)],
            vec![Fp::from(0)],  // gender check OFF
            vec![Fp::from(1)],
            vec![Fp::from(0)],  // nationality check OFF
            allowed_countries_fp,
        ];

        let prover = MockProver::run(8, &circuit, public_inputs).unwrap();
        prover.assert_satisfied();
    }


}