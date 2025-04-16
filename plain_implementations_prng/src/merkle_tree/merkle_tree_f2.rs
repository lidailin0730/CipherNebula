use sha2::{
    digest::{FixedOutputReset, Output},
    Digest,
};

#[derive(Clone, Debug)]
pub struct MerkleTree<F: Digest + FixedOutputReset + Clone> {
    hasher: F,
}

impl<F: Digest + FixedOutputReset + Clone> Default for MerkleTree<F> {
    fn default() -> Self {
        MerkleTree { hasher: F::new() }
    }
}

impl<F: Digest + FixedOutputReset + Clone> MerkleTree<F> {
    pub fn new() -> Self {
        MerkleTree { hasher: F::new() }
    }

    fn round_up_pow_n(input: usize, n: usize) -> usize {
        debug_assert!(n >= 1);
        let mut res = 1;
        // try powers, starting from n
        loop {
            res *= n;
            if res >= input {
                break;
            }
        }
        res
    }

    fn compress(&mut self, input: &[&Output<F>; 2]) -> Output<F> {
        <F as Digest>::update(&mut self.hasher, input[0]);
        <F as Digest>::update(&mut self.hasher, input[1]);
        self.hasher.finalize_reset()
    }

    pub fn accumulate(&mut self, set: &[Output<F>]) -> Output<F> {
        let set_size = set.len();
        let mut bound = Self::round_up_pow_n(set_size, 2);
        loop {
            if bound >= 2 {
                break;
            }
            bound *= 2;
        }
        let mut nodes: Vec<Output<F>> = Vec::with_capacity(bound);
        for s in set {
            nodes.push(s.to_owned());
        }
        // pad
        for _ in nodes.len()..bound {
            nodes.push(nodes[set_size - 1].to_owned());
        }

        while nodes.len() > 1 {
            let new_len = nodes.len() / 2;
            let mut new_nodes: Vec<Output<F>> = Vec::with_capacity(new_len);
            for i in (0..nodes.len()).step_by(2) {
                let inp = [&nodes[i], &nodes[i + 1]];
                let dig = self.compress(&inp);
                new_nodes.push(dig);
            }
            nodes = new_nodes;
        }
        nodes[0].to_owned()
    }
}
