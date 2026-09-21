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
}

fn main() {}