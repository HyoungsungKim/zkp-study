// Poseidon-based Bloom filter nationality check circuit in Halo2

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector, Expression},
    poly::Rotation,
};
use group::ff::PrimeField;

use crate::constants::MAX_COUNTRY_NUMBER;


#[derive(Default)]
pub struct NationalityCheckCircuit<F: PrimeField> {
    pub prover_country_code: Value<F>,
    //country_codes: Vec<Value<Fp>>, // Expecting 256 bits
}

#[derive(Clone, Debug)]
pub struct NationalityCheckConfig {
    pub prover_country_code: Column<Advice>,

    pub nationality_check_flag_advice: Column<Advice>,
    pub nationality_check_flag_instance: Column<Instance>, 

    pub required_country_codes_advice: Column<Advice>,
    pub required_country_codes_instance: Column<Instance>, // Expecting 256 bits
    pub selector: Selector,
}

impl <F: PrimeField> Circuit<F> for NationalityCheckCircuit<F> {
    type Config = NationalityCheckConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let prover_country_code = meta.advice_column();
            let nationality_check_flag_advice = meta.advice_column();
            let nationality_check_flag_instance = meta.instance_column(); // Expecting 256 bits
            let required_country_codes_advice = meta.advice_column();
            let required_country_codes_instance = meta.instance_column();
            let selector = meta.selector();

            meta.enable_equality(prover_country_code);
            meta.enable_equality(nationality_check_flag_advice);
            meta.enable_equality(nationality_check_flag_instance);
            meta.enable_equality(required_country_codes_advice);
            meta.enable_equality(required_country_codes_instance);

            meta.create_gate("check if input in list", |meta| {
                let sel = meta.query_selector(selector);
                let nationality_check_flag_advice = meta.query_advice(nationality_check_flag_advice, Rotation::cur());
                let prover_code = meta.query_advice(prover_country_code, Rotation::cur());

                let mut product = Expression::Constant(F::from(1));

                for i in 0..MAX_COUNTRY_NUMBER {
                    let code_i = meta.query_advice(required_country_codes_advice, Rotation(i as i32));
                    let diff = prover_code.clone() - code_i;
                    product = product * diff;
                }

                vec![sel * nationality_check_flag_advice* product]
            });

            NationalityCheckConfig {
                prover_country_code,
                nationality_check_flag_advice,
                nationality_check_flag_instance,
                required_country_codes_advice,
                required_country_codes_instance,
                selector,
            }
        }
    
    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        
        layouter.assign_region(
            || "country code check",
            |mut region| {
                region.assign_advice(
                    || "prover country code",
                    config.prover_country_code,
                    0,
                    ||self.prover_country_code,
                )?;

                region.assign_advice_from_instance(
                    || "load flag instance to advice",
                   config.nationality_check_flag_instance,
                    0,
                   config.nationality_check_flag_advice,
                    0,
                )?;

                for i in 0..MAX_COUNTRY_NUMBER {
                        region.assign_advice_from_instance(
                            || format!("country code {}", i),
                            config.required_country_codes_instance,
                            i,
                            config.required_country_codes_advice,
                            i,
                    )?;
                }
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

    let prover_country_code = Fp::from(410);
    let flag = Fp::from(1);
    let country_codes_pass = vec![Fp::from(410), Fp::from(840), Fp::from(0), Fp::from(0), Fp::from(0)];
    let country_codes_fail = vec![Fp::from(826), Fp::from(840), Fp::from(0), Fp::from(0), Fp::from(0)];

    let circuit = NationalityCheckCircuit {
        prover_country_code: Value::known(prover_country_code),
    };

    let public_inputs_0 = vec![vec![flag.clone()], country_codes_pass.clone()];
    let public_inputs_1 = vec![vec![flag.clone()], country_codes_fail.clone()];

    // Pass    
    let prover1 = MockProver::run(8, &circuit, public_inputs_0).unwrap();
    // Fail
    let prover2 = MockProver::run(8, &circuit, public_inputs_1).unwrap();
    prover1.assert_satisfied();
    assert!(prover2.verify().is_err()); 
}
