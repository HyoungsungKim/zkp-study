use halo2_proofs::{
    circuit::{Value, Region},
    plonk::{Advice, Column, ConstraintSystem, Error, Instance, Selector},
    poly::Rotation,
    pasta::Fp,
};
use group::ff::PrimeField;

#[derive(Clone, Debug)]
pub struct AddConfig {
    pub sum: Column<Instance>, 

    pub a: Column<Advice>,
    pub b: Column<Advice>,
    pub s_add: Selector, // Selector for the addition gate
}

pub struct AddChip<F: PrimeField> {
    pub config: AddConfig,
    pub _marker: std::marker::PhantomData<F>
}

impl <F: PrimeField> AddChip<F> {
    pub fn construct(config: AddConfig) -> Self {
        Self { 
            config, 
            _marker: std::marker::PhantomData 
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
    ) -> AddConfig {
        
        let sum = meta.instance_column();
        let a = meta.advice_column();
        let b = meta.advice_column();  // Assuming we have two inputs for addition
        let s_add = meta.selector();

        
        meta.create_gate(
            "add gate",
            |meta| {
                let s_add = meta.query_selector(s_add);
                let a = meta.query_advice(a, Rotation::cur());
                let b = meta.query_advice(b, Rotation::cur());
                let sum = meta.query_instance(sum, Rotation::cur());

                vec![s_add * (a + b - sum)]
            }
        );
        AddConfig { 
            s_add, 
            sum, 
            a, 
            b 
        }
    }

    pub fn assign_region(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        a: Value<F>,
        b: Value<F>
    ) -> Result<(), Error> {
        let config = &self.config;
        config.s_add.enable(region, offset)?;

        region.assign_advice(|| "a", config.a, offset, || a)?;
        region.assign_advice(|| "b", config.b, offset, || b)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::pasta::Fp;
    use halo2_proofs::circuit::{Value, SimpleFloorPlanner, Layouter};
    use halo2_proofs::plonk::{Circuit, ConstraintSystem};

    #[derive(Default, Clone, Debug)]
    struct DummyCircuit {
        pub a: Value<Fp>,
        pub b: Value<Fp>,
    }


    impl Circuit<Fp> for DummyCircuit {
        type Config = AddConfig;
        type FloorPlanner = SimpleFloorPlanner;
        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let sum = meta.instance_column();
            let a = meta.advice_column();
            let b = meta.advice_column();

            meta.enable_equality(sum);
            meta.enable_equality(a);
            meta.enable_equality(b);
            AddChip::<Fp>::configure(
                meta,
            )
        }
        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
            let chip = AddChip::construct(config.clone());            
            // Load the private values into the circuit.
            layouter.assign_region(
                || "load a and b",
                |mut region| {
                    chip.assign_region(
                        &mut region,
                        0,
                        self.a,
                        self.b,
                    )
                },
            )?;
            Ok(())
        }
    }

    #[test]
    fn test_add_chip_pass() {
        use halo2_proofs::dev::MockProver;
        let a = 5;
        let b = 3;
        let sum = a.clone() + b.clone();
        let circuit = DummyCircuit { a: Value::known(Fp::from(a)), b: Value::known(Fp::from(b)) };
        let public_inputs = vec![vec![Fp::from(sum)]];
        let prover = MockProver::run(4, &circuit, public_inputs).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_add_chip_fail() {
        use halo2_proofs::dev::MockProver;
        let a = 5;
        let b = 3;
        let incorrect_sum = a.clone() + b.clone() + 1; // Incorrect sum to cause failure
        let circuit = DummyCircuit { a: Value::known(Fp::from(a)), b: Value::known(Fp::from(b)) };
        let public_inputs = vec![vec![Fp::from(incorrect_sum)]];
        let prover = MockProver::run(4, &circuit, public_inputs).unwrap();
        assert!(prover.verify().is_err());
    }
}
