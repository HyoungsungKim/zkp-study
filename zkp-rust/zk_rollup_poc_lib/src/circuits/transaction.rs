use halo2_proofs::{
    circuit::{Value, Region},
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation
};
use halo2_gadgets::utilities::range_check;
use group::ff::PrimeField;

use crate::constants::MAX_BALANCE;


#[derive(Clone, Debug)]
pub struct TransactionConfig {
    pub sender_balance_before: Column<Advice>,
    pub receiver_balance_before: Column<Advice>,

    pub transaction_amount: Column<Advice>,

    pub sender_balance_after: Column<Advice>,
    pub receiver_balance_after: Column<Advice>,

    pub s_tx: Selector,
}

pub struct TransactionChip<F: PrimeField> {
    pub config: TransactionConfig,
    pub _marker: std::marker::PhantomData<F>,
}

impl <F: PrimeField> TransactionChip<F> {
    pub fn construct(config: TransactionConfig) -> Self {
        Self {
            config,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        sender_balance_before: Column<Advice>,
        receiver_balance_before: Column<Advice>,
        transaction_amount: Column<Advice>,
        sender_balance_after: Column<Advice>,
        receiver_balance_after: Column<Advice>,
    ) -> TransactionConfig {
        let s_tx = meta.selector();

        meta.enable_equality(sender_balance_before);
        meta.enable_equality(receiver_balance_before);

        meta.enable_equality(transaction_amount);

        meta.enable_equality(sender_balance_after);
        meta.enable_equality(receiver_balance_after);

        meta.create_gate("transaction", |meta| {
            let s_tx = meta.query_selector(s_tx);
            let sender_balance_before = meta.query_advice(sender_balance_before, Rotation::cur());
            let receiver_balance_before = meta.query_advice(receiver_balance_before, Rotation::cur());
            let transaction_amount = meta.query_advice(transaction_amount, Rotation::cur());
            let sender_balance_after = meta.query_advice(sender_balance_after, Rotation::cur());
            let receiver_balance_after = meta.query_advice(receiver_balance_after, Rotation::cur());

            // Constraint 1: Sender_balance_before >= transaction_amount
            // Constraint 2: sender_balance_before - transaction_amount == sender_balance_after
            // Constraint 3: receiver_balance_before + transaction_amount == receiver_balance_after

            let expr1 = range_check(sender_balance_before.clone() - transaction_amount.clone(), MAX_BALANCE);
            let expr2 = sender_balance_before.clone() - transaction_amount.clone() - sender_balance_after.clone();
            let expr3 = receiver_balance_before.clone() + transaction_amount.clone() - receiver_balance_after.clone();
            vec![s_tx * (expr1 + expr2 + expr3)]
    });

        TransactionConfig {
            sender_balance_before,
            receiver_balance_before,
            transaction_amount,
            sender_balance_after,
            receiver_balance_after,
            s_tx,
        }
    }

    pub fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        sender_balance_before: Value<F>,
        receiver_balance_before: Value<F>,
        transaction_amount: Value<F>,
        sender_balance_after: Value<F>,
        receiver_balance_after: Value<F>,
    ) -> Result<(), Error> {
        self.config.s_tx.enable(region, offset)?;
        region.assign_advice(|| "sender_balance_before", self.config.sender_balance_before, offset, || sender_balance_before)?;
        region.assign_advice(|| "receiver_balance_before", self.config.receiver_balance_before, offset, || receiver_balance_before)?;
        region.assign_advice(|| "transaction_amount", self.config.transaction_amount, offset, || transaction_amount)?;
        region.assign_advice(|| "sender_balance_after", self.config.sender_balance_after, offset, || sender_balance_after)?;
        region.assign_advice(|| "receiver_balance_after", self.config.receiver_balance_after, offset, || receiver_balance_after)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*; // chip 코드 가져오기
    use halo2_proofs::{dev::MockProver, pasta::Fp, circuit::{Layouter, Value, SimpleFloorPlanner}, plonk::{Circuit, ConstraintSystem, Error}};

    struct DummyCircuit<F: PrimeField> {
        pub sender_balance_before: Value<F>,
        pub receiver_balance_before: Value<F>,
        pub transaction_amount: Value<F>,
        pub sender_balance_after: Value<F>,
        pub receiver_balance_after: Value<F>,
    }

    impl<F: PrimeField> Circuit<F> for DummyCircuit<F> {
        type Config = TransactionConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                sender_balance_before: Value::unknown(),
                receiver_balance_before: Value::unknown(),
                transaction_amount: Value::unknown(),
                sender_balance_after: Value::unknown(),
                receiver_balance_after: Value::unknown(),
            }
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let sender_balance_before_advice = meta.advice_column();
            let receiver_balance_before_advice = meta.advice_column();
            let transaction_amount_advice = meta.advice_column();
            let sender_balance_after_advice = meta.advice_column();
            let receiver_balance_after_advice = meta.advice_column();
            TransactionChip::configure(
                meta,
                sender_balance_before_advice,
                receiver_balance_before_advice,
                transaction_amount_advice,
                sender_balance_after_advice,
                receiver_balance_after_advice
            )
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
            let chip = TransactionChip::construct(config);

            layouter.assign_region(
                || "transaction check",
                |mut region| {
                chip.assign(
                    &mut region,
                    0,
                    self.sender_balance_before,
                    self.receiver_balance_before,
                    self.transaction_amount,
                    self.sender_balance_after,
                    self.receiver_balance_after
                )
            })?;
            Ok(())
        }
    }

    #[test]
    fn test_age_transaction_pass() {
        let sender_balance_before = Fp::from(100);
        let receiver_balance_before = Fp::from(0);
        let transaction_amount = Fp::from(50);
        let sender_balance_after = sender_balance_before.clone() - transaction_amount.clone();
        let receiver_balance_after = receiver_balance_before.clone() + transaction_amount.clone();
        let circuit = DummyCircuit {
            sender_balance_before: Value::known(sender_balance_before),
            receiver_balance_before: Value::known(receiver_balance_before),
            transaction_amount: Value::known(transaction_amount),
            sender_balance_after: Value::known(sender_balance_after),
            receiver_balance_after: Value::known(receiver_balance_after),
        };

        let public_inputs = vec![];

        let prover = MockProver::run(4, &circuit, public_inputs).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_age_minus_balance_fail() {
        let sender_balance_before = Fp::from(100);
        let receiver_balance_before = Fp::from(0);
        let transaction_amount = Fp::from(150);
        let sender_balance_after = sender_balance_before.clone() - transaction_amount.clone();
        let receiver_balance_after = receiver_balance_before.clone() + transaction_amount.clone();
        let circuit = DummyCircuit {
            sender_balance_before: Value::known(sender_balance_before),
            receiver_balance_before: Value::known(receiver_balance_before),
            transaction_amount: Value::known(transaction_amount),
            sender_balance_after: Value::known(sender_balance_after),
            receiver_balance_after: Value::known(receiver_balance_after),
        };

        let public_inputs = vec![];

        let prover = MockProver::run(4, &circuit, public_inputs).unwrap();
        assert!(prover.verify().is_err()); 
    }
}
