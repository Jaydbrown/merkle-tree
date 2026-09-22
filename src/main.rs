use sha2::{Digest, Sha256};
use primitive_types::U256;

struct MerkleLeaf{
    id: u64,
    hash: [u8; 32],
}

struct MerkleTree {
    leaves: Vec<MerkleLeaf>,
    next_Id: u64,
    level: u64
}

impl MerkleTree{
   fn parentHash(&mut self, left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
        let a = U256::from_big_endian(&left);
        let b = U256::from_big_endian(&right);
        let (sum, _) = a.overflowing_add(b);   

        let mut parent = sum.to_big_endian();

        let hashedParent = Sha256::digest(parent);
        self.level += 1;
        Sha256::digest(hashedParent).into()  // prevents length extension attack
    }

    fn  add_leaf(&mut self, data: &[u8]) -> [0u8; 32] {
        let mut input = vec![0u8];
        input.extend_from_slice(data);
        let hash: [u8; 32] = Sha256::digest(&input).into();
        self.leaves.push(MerkleLeaf {id: self.next_Id, hash});
        self.next_Id += 1;
        hash
    }

   fn build_root(&mut self) -> [u8; 32] {
    let mut level: Vec<[u8; 32]> = self.leaves.iter().map(|l| l.hash).collect();

    while level.len() > 1 {
        let mut next_level = Vec::new();
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() { level[i + 1] } else { left };
            next_level.push(self.parentHash(left, right));
            i += 2;
        }
        level = next_level;
    }

    level[0]
}

}

fn main() {}