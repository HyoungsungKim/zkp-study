use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, Value},
    pasta::Fp,
    plonk::{Advice, Column, ConstraintSystem, Error, Instance}
};
use halo2_gadgets::poseidon::primitives::Spec;

use super::poseidon_chip::{PoseidonChip, PoseidonConfig};

#[derive(Debug, Clone)]
pub struct MerkleTreeConfig<const WIDTH: usize, const RATE: usize, const L: usize> {
    pub inputs: Vec<Column<Advice>>,
    pub poseidon_config: PoseidonConfig<WIDTH, RATE, L>,
}

pub struct MerkleTreeChip<
    S: Spec<Fp, WIDTH, RATE>,
    const WIDTH: usize,
    const RATE: usize,
    const L: usize,
> {
    config: MerkleTreeConfig<WIDTH, RATE, L>,
   _marker: std::marker::PhantomData<S>,
}

impl <S: Spec<Fp, WIDTH, RATE>, const WIDTH: usize, const RATE: usize, const L: usize>
MerkleTreeChip<S, WIDTH, RATE, L> {
    pub fn construct(config: MerkleTreeConfig<WIDTH, RATE, L>) -> Self {
        Self { config, _marker: std::marker::PhantomData }
    }

    pub fn configure(meta: &mut ConstraintSystem<Fp>, inputs: Vec<Column<Advice>>) -> MerkleTreeConfig<WIDTH, RATE, L> {
        let poseidon_config = PoseidonChip::<S, WIDTH, RATE, L>::configure(meta);
        for input in &inputs {
            meta.enable_equality(*input);
        }

        MerkleTreeConfig { inputs, poseidon_config }
    }

    pub fn assign(
        &self,
        region: &mut Region<'_, Fp>,
        offset: usize,
        inputs: [Value<Fp>; L]
    ) -> Result<(), Error> {
        for (i, input) in inputs.iter().enumerate() {
            region.assign_advice(
                || format!("input {}", i),
                self.config.inputs[i],
                offset,
                || *input
            )?;
        }
        Ok(())
    }

    pub fn compute_merkle_root(
        &self,
        layouter: &mut impl Layouter<Fp>,
        leaves: &[AssignedCell<Fp, Fp>],
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        assert!(leaves.len().is_power_of_two()); // 패딩 전제

        let mut current_layer = leaves.to_vec();
        let chip = PoseidonChip::<S, WIDTH, RATE, L>::construct(self.config.poseidon_config.clone());

        while current_layer.len() > 1 {
            let mut next_layer = vec![];
            for i in (0..current_layer.len()).step_by(2) {
                let left = current_layer[i].clone();
                let right = current_layer[i + 1].clone();

                let parent = chip.hash(
                    layouter.namespace(|| format!("hash({i})")),
                    &[left, right]
                )?;
                next_layer.push(parent);
            }
            current_layer = next_layer;
        }

        Ok(current_layer[0].clone()) // Merkle Root
    }

    pub fn verify_inclusion_proof(
        &self,
        mut layouter: impl Layouter<Fp>,
        leaf: AssignedCell<Fp, Fp>,
        proof: &[AssignedCell<Fp, Fp>],
        path_bits: &[bool],
        expected_root: AssignedCell<Fp, Fp>,
    ) -> Result<(), Error> {
        assert_eq!(proof.len(), path_bits.len());
        let chip = PoseidonChip::<S, WIDTH, RATE, L>::construct(self.config.poseidon_config.clone());
        let mut current = leaf.clone();

        for (i, (sibling, bit)) in proof.iter().zip(path_bits.iter()).enumerate() {
            let inputs = if *bit {
                [sibling.clone(), current]
            } else {
                [current, sibling.clone()]
            };

            current = chip.hash(layouter.namespace(|| format!("path hash {}", i)), &inputs)?;
        }
        layouter.assign_region(
            || "verify root",
            |mut region| -> Result<(), Error> {
                region.constrain_equal(current.cell(), expected_root.cell())?;
                Ok(())
            },
        )?;
        Ok(())
    }

    pub fn expose_public(
        &self,
        layouter: &mut impl Layouter<Fp>,
        cell: &AssignedCell<Fp, Fp>,
        instance: Column<Instance>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(cell.cell(), instance, row)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        pasta::Fp,
        plonk::{Circuit, ConstraintSystem, Error},
    };
    use halo2_gadgets::poseidon::primitives::P128Pow5T3;
    use crate::utils::{build_merkle_tree, get_merkle_proof};

    const WIDTH: usize = 3;
    const RATE: usize = 2;
    const L: usize = 2;

    #[derive(Default)]
    struct MerkleInclusionCircuit {
        leaf: Value<Fp>,
        proof: Vec<Value<Fp>>,
        path_bits: Vec<bool>,
        expected_root: Value<Fp>,
    }

    impl Circuit<Fp> for MerkleInclusionCircuit {
        type Config = MerkleTreeConfig<WIDTH, RATE, L>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                leaf: Value::unknown(),
                proof: vec![Value::unknown(); self.proof.len()],
                path_bits: self.path_bits.clone(),
                expected_root: Value::unknown(),
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let inputs = (0..2).map(|_| meta.advice_column()).collect();
            MerkleTreeChip::<P128Pow5T3, WIDTH, RATE, L>::configure(meta, inputs)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let chip = MerkleTreeChip::<P128Pow5T3, WIDTH, RATE, L>::construct(config);

            // Leaf 할당
            let assigned_leaf = layouter.assign_region(
                || "assign leaf",
                |mut region| {
                    region.assign_advice(
                        || "leaf",
                        chip.config.inputs[0],
                        0,
                        || self.leaf,
                    )
                },
            )?;

            // Proof 할당
            let assigned_proof: Vec<AssignedCell<Fp, Fp>> = self.proof
                .iter()
                .enumerate()
                .map(|(i, val)| {
                    layouter.assign_region(
                        || format!("assign proof {}", i),
                        |mut region| {
                            region.assign_advice(
                                || format!("proof {}", i),
                                chip.config.inputs[0],
                                0,
                                || *val,
                            )
                        },
                    )
                })
                .collect::<Result<_, _>>()?;

            // Root 할당
            let assigned_root = layouter.assign_region(
                || "assign expected root",
                |mut region| {
                    region.assign_advice(
                        || "expected root",
                        chip.config.inputs[0],
                        0,
                        || self.expected_root,
                    )
                },
            )?;

            chip.verify_inclusion_proof(
                layouter,
                assigned_leaf,
                &assigned_proof,
                &self.path_bits,
                assigned_root,
            )
        }
    }

    #[test]
    fn test_merkle_inclusion_proof() {
        let leaves: Vec<Fp> = (0..8).map(|i| Fp::from(i as u64)).collect(); // leaf 8개
        let tree = build_merkle_tree(&leaves);
        let root = tree.last().unwrap()[0];
        let leaf_index = 3;
        let leaf = leaves[leaf_index];
        let (proof, path_bits) = get_merkle_proof(&tree, leaf_index);

        let circuit = MerkleInclusionCircuit {
            leaf: Value::known(leaf),
            proof: proof.iter().cloned().map(Value::known).collect(),
            path_bits,
            expected_root: Value::known(root),
        };

        let prover = MockProver::run(10, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }
}
