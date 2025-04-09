use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
    pasta::Fp,
};
use halo2_gadgets::poseidon::primitives::P128Pow5T3;
use array_init::array_init;

use crate::constants::{POSEIDON_RATE, POSEIDON_WIDTH, POSEIDON_INPUTS, TX_FIELDS_COUNT, TX_AGGREGATION_COUNT};
use crate::circuits::transaction_chips::{TransactionChip, TransactionConfig};
use crate::circuits::merkle_tree_chip::{MerkleTreeChip, MerkleTreeConfig};
use crate::circuits::poseidon_chip::PoseidonChip;

#[derive(Clone)]
pub struct ZKRollupConfig{
    pub root_hash_instance: Column<Instance>,

    /*
    Number of transaciton fields: 7
    - sender_balance_before
    - receiver_balance_before
    - transaction_amount
    - sender_balance_after
    - receiver_balance_after
    - sender_address -> Currently commented in transaciton_chip.rs
    - receiver_address -> Currently commented in transaciton_chip.rs
     */
    pub tx_aggregation_advice: [[Column<Advice>; TX_FIELDS_COUNT]; TX_AGGREGATION_COUNT],
}

#[derive(Default, Clone)]
pub struct ZKRollupCircuit {
    pub tx_aggregations: [[Value<Fp>; TX_FIELDS_COUNT]; TX_AGGREGATION_COUNT],
}

impl Circuit<Fp> for ZKRollupCircuit {
    type Config = (ZKRollupConfig, TransactionConfig, MerkleTreeConfig<POSEIDON_WIDTH, POSEIDON_RATE, POSEIDON_INPUTS>);
    type FloorPlanner = halo2_proofs::circuit::SimpleFloorPlanner;
 
    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let root_hash_instance = meta.instance_column();
        meta.enable_equality(root_hash_instance);


        // compile-time 배열 생성
        let tx_aggregation_advice: [[Column<Advice>; TX_FIELDS_COUNT]; TX_AGGREGATION_COUNT] =
        array_init(|_| {
            array_init(|_| {
                let col = meta.advice_column();
                meta.enable_equality(col);
                col
            })
        });

        // 트랜잭션 관련 config (넣을 컬럼들 지정해야 함)
        let sender = meta.advice_column();
        let receiver = meta.advice_column();
        let amount = meta.advice_column();
        let sender_after = meta.advice_column();
        let receiver_after = meta.advice_column();

        let tx_config = TransactionChip::<Fp>::configure(
            meta,
            sender,
            receiver,
            amount,
            sender_after,
            receiver_after,
        );

            // MerkleTree config 준비
        let mt_config = MerkleTreeChip::<P128Pow5T3, POSEIDON_WIDTH, POSEIDON_RATE, POSEIDON_INPUTS>::configure(
            meta,
            tx_aggregation_advice[0].to_vec(),
        );

        let zk_config = ZKRollupConfig {
            root_hash_instance,
            tx_aggregation_advice,
        };
                
        (zk_config, tx_config, mt_config)
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let (zk_config, tx_config, mt_config) = config;
        let tx_chip = TransactionChip::<Fp>::construct(tx_config);
        let mt_chip: MerkleTreeChip<P128Pow5T3, 3, 2, 2> = MerkleTreeChip::<P128Pow5T3, POSEIDON_WIDTH, POSEIDON_RATE, POSEIDON_INPUTS>::construct(mt_config.clone());

        let mut tx_hashes = vec![];
        for (i, tx_fields) in self.tx_aggregations.iter().enumerate() {
            let assigned_fields = layouter.assign_region(
                || format!("tx {i} fields"),
                |mut region| {
                    let mut cells = vec![];
                    for j in 0.. TX_FIELDS_COUNT {
                        let cell = region.assign_advice(
                            || format!("tx_{i} foeld_{j}"),
                            zk_config.tx_aggregation_advice[i][j],
                            j,
                            || tx_fields[j],
                        )?;
                        cells.push(cell);
                }
                tx_chip.assign(
                    &mut region,
                    0,
                    tx_fields[0],
                    tx_fields[1],
                    tx_fields[2],
                    tx_fields[3],
                    tx_fields[4],
                )?;

                Ok(cells.try_into().unwrap())
            })?;
            // 3. tx_compress()로 Poseidon 해시 계산
            let poseidon_chip = PoseidonChip::<P128Pow5T3, POSEIDON_WIDTH, POSEIDON_RATE, 2>::construct(mt_config.poseidon_config.clone());
            let tx_hash = tx_chip.tx_compress(&mut layouter, &poseidon_chip, &assigned_fields)?;
            tx_hashes.push(tx_hash);
        };

        // 4. Merkle 루트 계산
        let root_cell = mt_chip.compute_merkle_root(&mut layouter, &tx_hashes)?;

        // 5. Merkle 루트를 공개 인스턴스와 비교
        mt_chip.expose_public(&mut layouter, &root_cell, zk_config.root_hash_instance, 0)?;

        Ok(())
    }

}