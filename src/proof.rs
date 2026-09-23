use sha2::{Digest, Sha256};
use primitive_types::U256;

use crate::MerkleTree;

pub struct ProofStep {
    pub sibling: [u8; 32],
    pub sibling_is_left: bool,
}

// same left/right combination rule as MerkleTree::parentHash, kept standalone
// so verification doesn't need a live MerkleTree instance.
fn combine(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let a = U256::from_big_endian(&left);
    let b = U256::from_big_endian(&right);
    let (sum, _) = a.overflowing_add(b);
    let parent = sum.to_big_endian();
    let hashed_parent = Sha256::digest(parent);
    Sha256::digest(hashed_parent).into()
}

impl MerkleTree {
    pub fn get_proof(&self, leaf_index: usize) -> Option<Vec<ProofStep>> {
        if leaf_index >= self.leaves.len() {
            return None;
        }

        let mut level: Vec<[u8; 32]> = self.leaves.iter().map(|l| l.hash).collect();
        let mut index = leaf_index;
        let mut proof = Vec::new();

        while level.len() > 1 {
            let mut next_level = Vec::new();
            let mut i = 0;
            while i < level.len() {
                let left = level[i];
                let right = if i + 1 < level.len() { level[i + 1] } else { left };

                if i == index {
                    proof.push(ProofStep { sibling: right, sibling_is_left: false });
                } else if i + 1 == index {
                    proof.push(ProofStep { sibling: left, sibling_is_left: true });
                }

                next_level.push(combine(left, right));
                i += 2;
            }
            index /= 2;
            level = next_level;
        }

        Some(proof)
    }
}

pub fn verify_proof(leaf_hash: [u8; 32], proof: &[ProofStep], root: [u8; 32]) -> bool {
    let mut current = leaf_hash;
    for step in proof {
        current = if step.sibling_is_left {
            combine(step.sibling, current)
        } else {
            combine(current, step.sibling)
        };
    }
    current == root
}
