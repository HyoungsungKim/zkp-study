use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value, Region},
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
    pasta::Fp,
};
use halo2_gadgets::utilities::range_check;
use group::ff::PrimeField;
use halo2_gadgets::poseidon::primitives::Spec;

use crate::constants::{MAX_BALANCE, POSEIDON_RATE, POSEIDON_WIDTH};
use crate::circuits::poseidon_chip::PoseidonChip;


#[derive(Clone, Debug)]
pub struct TransactionConfig {
    pub sender_balance_before: Column<Advice>,
    pub receiver_balance_before: Column<Advice>,

    pub transaction_amount: Column<Advice>,

    pub sender_balance_after: Column<Advice>,
    pub receiver_balance_after: Column<Advice>,

    //pub sender_address: Column<Advice>,
    //pub receiver_address: Column<Advice>,

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
        meta: &mut ConstraintSystem<Fp>,
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

    pub fn tx_compress(
        &self,
        layouter: &mut impl Layouter<Fp>,
        chip: &PoseidonChip<impl Spec<Fp, POSEIDON_WIDTH, POSEIDON_RATE>, POSEIDON_WIDTH, POSEIDON_RATE, 2>,
        fields: &[AssignedCell<Fp, Fp>; 7],
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let h1 = chip.hash(layouter.namespace(|| "h1"), &[fields[0].clone(), fields[1].clone()])?;
        let h2 = chip.hash(layouter.namespace(|| "h2"), &[fields[2].clone(), fields[3].clone()])?;
        let h3 = chip.hash(layouter.namespace(|| "h3"), &[fields[4].clone(), fields[5].clone()])?;
        let zero = chip.assign_constant(layouter, Fp::from(0))?;
        let padded = chip.hash(layouter.namespace(|| "pad"), &[fields[6].clone(), zero])?;
    
        let left = chip.hash(layouter.namespace(|| "left"), &[h1, h2])?;
        let right = chip.hash(layouter.namespace(|| "right"), &[h3, padded])?;
        chip.hash(layouter.namespace(|| "final"), &[left, right])
    }
}

#[cfg(test)]
mod tests {
    use super::*; // chip 코드 가져오기
    use halo2_proofs::{dev::MockProver, pasta::Fp, circuit::{Layouter, Value, SimpleFloorPlanner}, plonk::{Circuit, ConstraintSystem, Error}};
    use crate::circuits::poseidon_chip::{PoseidonChip, PoseidonConfig};
    use halo2_gadgets::poseidon::primitives::P128Pow5T3;

    const WIDTH: usize = 3;
    const RATE: usize = 2;
    const L: usize = 2;

    struct DummyCircuit {
        pub sender_balance_before: Value<Fp>,
        pub receiver_balance_before: Value<Fp>,
        pub transaction_amount: Value<Fp>,
        pub sender_balance_after: Value<Fp>,
        pub receiver_balance_after: Value<Fp>,
        pub poseidon_config: Option<PoseidonConfig<3, 2, 2>>,
    }

    impl Circuit<Fp> for DummyCircuit {
        type Config = (TransactionConfig, PoseidonConfig<WIDTH, RATE, L>);
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                sender_balance_before: Value::unknown(),
                receiver_balance_before: Value::unknown(),
                transaction_amount: Value::unknown(),
                sender_balance_after: Value::unknown(),
                receiver_balance_after: Value::unknown(),
                poseidon_config: self.poseidon_config.clone(), // Assuming PoseidonConfig is Clone
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let sender_balance_before_advice = meta.advice_column();
            let receiver_balance_before_advice = meta.advice_column();
            let transaction_amount_advice = meta.advice_column();
            let sender_balance_after_advice = meta.advice_column();
            let receiver_balance_after_advice = meta.advice_column();
        
            let tx_config = TransactionChip::<Fp>::configure(
                meta,
                sender_balance_before_advice,
                receiver_balance_before_advice,
                transaction_amount_advice,
                sender_balance_after_advice,
                receiver_balance_after_advice
            );
        
            let poseidon_config = PoseidonChip::<P128Pow5T3, 3, 2, 2>::configure(meta);
            (tx_config, poseidon_config)
        }

        fn synthesize(
            &self,
            (tx_config, poseidon_config): Self::Config,
            mut layouter: impl Layouter<Fp>
        ) -> Result<(), Error> {
            let tx_chip = TransactionChip::construct(tx_config.clone());
            let poseidon_chip = PoseidonChip::<P128Pow5T3, 3, 2, 2>::construct(poseidon_config);
        
            layouter.assign_region(
                || "transaction check",
                |mut region| {
                    tx_chip.assign(
                        &mut region,
                        0,
                        self.sender_balance_before,
                        self.receiver_balance_before,
                        self.transaction_amount,
                        self.sender_balance_after,
                        self.receiver_balance_after,
                    )
                },
            )?;
        
            // Poseidon 해시를 위한 field 할당
            let assigned_fields = layouter.assign_region(
                || "assign fields for poseidon",
                |mut region| {
                    let mut assigned = vec![];
                    let vals = vec![
                        self.sender_balance_before,
                        self.receiver_balance_before,
                        self.transaction_amount,
                        self.sender_balance_after,
                        self.receiver_balance_after,
                        // temp sender and receiver address
                        Value::known(Fp::from(0)),
                        Value::known(Fp::from(0)),
                    ];
                    for (i, val) in vals.iter().enumerate() {
                        let cell = region.assign_advice(
                            || format!("field {}", i),
                            tx_config.sender_balance_before, // reuse 아무 advice column
                            i,
                            || *val,
                        )?;
                        assigned.push(cell);
                    }
                    Ok(assigned.try_into().unwrap())
                },
            )?;
        
            // 압축 해시 호출
            let hash = tx_chip.tx_compress(&mut layouter, &poseidon_chip, &assigned_fields)?;
            println!("▶ tx_compress hash = {:?}", hash.value());
        
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
            poseidon_config: None, // 실제 사용 안 함
        };

        let public_inputs = vec![];

        let prover = MockProver::run(9, &circuit, public_inputs).unwrap();
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
            poseidon_config: None, // 실제 사용 안 함
        };

        let public_inputs = vec![];

        let prover = MockProver::run(9, &circuit, public_inputs).unwrap();
        assert!(prover.verify().is_err()); 
    }

    #[test]
fn test_tx_compress() {
    use crate::utils::build_merkle_tree;

    let sender_balance_before = Fp::from(100);
    let receiver_balance_before = Fp::from(0);
    let transaction_amount = Fp::from(50);
    let sender_balance_after = sender_balance_before - transaction_amount;
    let receiver_balance_after = receiver_balance_before + transaction_amount;

    let inputs = vec![
        sender_balance_before,
        receiver_balance_before,
        transaction_amount,
        sender_balance_after,
        receiver_balance_after,
        Fp::zero(),
        Fp::zero(),
    ];
    let merkle_tree = build_merkle_tree(&inputs);
    let root_hash = merkle_tree.last().unwrap()[0];
    println!("▶ expected hash (off-circuit) = {:?}", root_hash);

    let circuit = DummyCircuit {
        sender_balance_before: Value::known(sender_balance_before),
        receiver_balance_before: Value::known(receiver_balance_before),
        transaction_amount: Value::known(transaction_amount),
        sender_balance_after: Value::known(sender_balance_after),
        receiver_balance_after: Value::known(receiver_balance_after),
        poseidon_config: None, // 실제 사용 안 함
    };

    let prover = MockProver::run(9, &circuit, vec![]).unwrap();
    prover.assert_satisfied();
}

}
