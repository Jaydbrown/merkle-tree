use sha2::{Digest, Sha256};

mod proof;

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
        let mut input = vec![1u8]; 
        input.extend_from_slice(&left);
        input.extend_from_slice(&right);

        let hashedParent = Sha256::digest(&input);
        self.level += 1;
        Sha256::digest(hashedParent).into()  // prevents length extension attack
    }

    fn  add_leaf(&mut self, data: &[u8]) -> [u8; 32] {
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

fn main() {
    let mut tree = MerkleTree {
        leaves: Vec::new(),
        next_Id: 0,
        level: 0,
    };

    tree.add_leaf(b"transaction 1");
    tree.add_leaf(b"transaction 2");
    tree.add_leaf(b"transaction 3");
    tree.add_leaf(b"transaction 4");

    let root = tree.build_root();

    let target_index = 2;
    let leaf_hash = tree.leaves[target_index].hash;
    let steps = tree.get_proof(target_index).expect("leaf exists");

    let valid = proof::verify_proof(leaf_hash, &steps, root);

    println!("root:  {:x?}", root);
    println!("proof steps: {}", steps.len());
    println!("leaf {} verifies: {}", target_index, valid);
}