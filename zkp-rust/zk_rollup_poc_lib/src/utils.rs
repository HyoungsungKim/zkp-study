use halo2_gadgets::poseidon::primitives::{
    ConstantLength, P128Pow5T3, Hash as PoseidonHash,
};
use halo2_proofs::pasta::Fp;
use halo2_proofs::{
    circuit::{Layouter, AssignedCell},
    plonk::{Instance, Column, Error},
};

pub fn expose_public(
    layouter: &mut impl Layouter<Fp>,
    cell: &AssignedCell<Fp, Fp>,
    instance: Column<Instance>,
    row: usize,
) -> Result<(), Error> {
    layouter.constrain_instance(cell.cell(), instance, row)
}


pub fn poseidon_hash(inputs: &[Fp; 2]) -> Fp {
    PoseidonHash::<_, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash(*inputs)
}

pub fn build_merkle_tree(hashes: &[Fp]) -> Vec<Vec<Fp>> {
    let mut padded = hashes.to_vec();
    let next_pow_of_2 = hashes.len().next_power_of_two();
    padded.resize(next_pow_of_2, Fp::zero());

    let mut tree = vec![padded];
    while tree.last().unwrap().len() > 1 {
        let layer = tree.last().unwrap();
        let mut next_layer = Vec::new();
        for i in (0..layer.len()).step_by(2) {
            if i + 1 < layer.len() {
                // Concatenate and hash the pair of nodes
                let concatenated = [layer[i], layer[i + 1]];
                let hash = poseidon_hash(&concatenated);
                next_layer.push(hash);
            } else {
                // If there's an odd number of nodes, duplicate the last node
                next_layer.push(layer[i]);
            }
        }
        tree.push(next_layer);
    }
    tree
}

pub fn get_merkle_proof(tree: &[Vec<Fp>], leaf_index: usize) -> (Vec<Fp>, Vec<bool>) {
    let mut index = leaf_index;
    let mut proof = vec![];
    let mut path_bits = vec![];

    for level in &tree[..tree.len() - 1] {
        let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
        if sibling_index < level.len() {
            proof.push(level[sibling_index]);
        } else {
            proof.push(level[index]); // padding
        }
        path_bits.push(index % 2 == 1); // right if odd
        index /= 2;
    }

    (proof, path_bits)
}