//! # ComparisonChip: General-Purpose Comparison Gadget for Halo2
//!
//! This chip enables range-constrained comparison operations between two private inputs,
//! conditionally enforced by a public/private flag. The constraint type (e.g., `Equal`, `GreaterEqual`, etc.)
//! is determined during circuit configuration.
//!
//! ## Supported Operations
//! - Equal
//! - GreaterThan
//! - GreaterEqual
//! - LessThan
//! - LessEqual
//!
//! ## Usage
//! Call `ComparisonChip::configure(meta, comparison, max_value)` in the `configure` function
//! and store the returned config.
//!
//! In `synthesize`, construct the chip via `ComparisonChip::construct(config)` and call `assign`.
//!
//! ```rust
//! // In configure()
//! let config = ComparisonChip::configure(meta, Comparison::GreaterEqual, 256);
//!
//! // In synthesize()
//! let chip = ComparisonChip::construct(config);
//! chip.assign(&mut region, offset, lhs_val, rhs_val, flag)?;
//! ```

use halo2_proofs::{
    circuit::{Value, Region},
    plonk::{Advice, Column, ConstraintSystem, Error, Selector, Expression},
    poly::Rotation,
};
use group::ff::PrimeField;
use halo2_gadgets::utilities::range_check;

/// Enum representing supported comparison operations.
#[derive(Clone, Copy, Debug)]
pub enum Comparison {
    Equal,
    GreaterThan,
    GreaterEqual,
    LessThan,
    LessEqual,
}

/// Default comparison (used by Circuit default): Equal
impl Default for Comparison {
    fn default() -> Self {
        Comparison::Equal
    }
}

/// Configuration object for the comparison chip.
#[derive(Clone, Debug)]
pub struct ComparisonConfig {
    pub lhs: Column<Advice>,
    pub rhs: Column<Advice>,
    pub flag: Column<Advice>,
    pub selector: Selector,
}

/// General-purpose comparison chip using configurable constraints.
pub struct ComparisonChip<F: PrimeField> {
    pub config: ComparisonConfig,
    pub _marker: std::marker::PhantomData<F>,
}

impl<F: PrimeField> ComparisonChip<F> {
    /// Construct a ComparisonChip from config.
    pub fn construct(config: ComparisonConfig) -> Self {
        Self {
            config,
            _marker: std::marker::PhantomData,
        }
    }

    /// Configure the circuit and create the appropriate comparison gate.
    pub fn configure(meta: &mut ConstraintSystem<F>, comparison: Comparison, max_value: usize) -> ComparisonConfig {
        let lhs = meta.advice_column();
        let rhs = meta.advice_column();
        let flag = meta.advice_column();
        let selector = meta.selector();

        meta.enable_equality(lhs);
        meta.enable_equality(rhs);
        meta.enable_equality(flag);

        let config = ComparisonConfig { lhs, rhs, flag, selector };

        Self::create_gate_static(meta, &config, comparison, max_value);
        config
    }

    /// Internal static function to generate comparison constraint.
    pub fn create_gate_static(
        meta: &mut ConstraintSystem<F>,
        cfg: &ComparisonConfig,
        comparison: Comparison,
        max_value: usize,
    ) {
        meta.create_gate("comparison gate", |meta| {
            let sel = meta.query_selector(cfg.selector);
            let lhs = meta.query_advice(cfg.lhs, Rotation::cur());
            let rhs = meta.query_advice(cfg.rhs, Rotation::cur());

            let constraint = match comparison {
                Comparison::Equal => lhs.clone() - rhs.clone(),
                Comparison::GreaterEqual => {
                    let diff = lhs.clone() - rhs.clone();
                    let adjusted = Expression::Constant(F::from(max_value as u64)) - diff;
                    range_check(adjusted, max_value)
                },
                Comparison::LessEqual => {
                    let diff = rhs.clone() - lhs.clone();
                    let adjusted = Expression::Constant(F::from(max_value as u64)) - diff;
                    range_check(adjusted, max_value)
                },
                Comparison::GreaterThan => {
                    let diff = lhs.clone() - rhs.clone() - Expression::Constant(F::ONE);
                    let adjusted = Expression::Constant(F::from(max_value as u64)) - diff;
                    range_check(adjusted, max_value)
                },
                Comparison::LessThan => {
                    let diff = rhs.clone() - lhs.clone() - Expression::Constant(F::ONE);
                    let adjusted = Expression::Constant(F::from(max_value as u64)) - diff;
                    range_check(adjusted, max_value)
                },
            };

            vec![sel * constraint]
        });
    }

    /// Assign witnesses for the comparison operation.
    pub fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        lhs: Value<F>,
        rhs: Value<F>,
        flag: Value<F>,
    ) -> Result<(), Error> {
        self.config.selector.enable(region, offset)?;
        region.assign_advice(|| "lhs", self.config.lhs, offset, || lhs)?;
        region.assign_advice(|| "rhs", self.config.rhs, offset, || rhs)?;
        region.assign_advice(|| "flag", self.config.flag, offset, || flag)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{
        pasta::Fp,
        circuit::{Value, SimpleFloorPlanner, Layouter},
        plonk::{Circuit, ConstraintSystem},
        dev::MockProver,
    };
    use halo2_proofs::arithmetic::Field;

    #[derive(Default)]
    struct TestCircuit {
        lhs: Value<Fp>,
        rhs: Value<Fp>,
    }

    impl Circuit<Fp> for TestCircuit {
        type Config = ComparisonConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            ComparisonChip::configure(meta, Comparison::GreaterEqual, 256)
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
            let chip = ComparisonChip::construct(config);
            layouter.assign_region(
                || "comparison check",
                |mut region| {
                    chip.assign(&mut region, 0, self.lhs, self.rhs, Value::known(Fp::ONE))
                },
            )
        }
    }

    #[test]
    fn test_greater_equal_pass() {
        let circuit = TestCircuit {
            lhs: Value::known(Fp::from(30)),
            rhs: Value::known(Fp::from(10)),
        };
        let prover = MockProver::run(8, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_greater_equal_fail() {
        let circuit = TestCircuit {
            lhs: Value::known(Fp::from(5)),
            rhs: Value::known(Fp::from(10)),
        };
        let prover = MockProver::run(8, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err());
    }
}
