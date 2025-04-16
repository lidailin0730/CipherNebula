use pasta_curves::pallas::Base;

type F = Base;

pub trait MerkleTreeHash {
    fn compress(&self, level: usize, input: &[&F; 2]) -> F;
}

#[derive(Clone, Debug)]
pub struct MerkleTree<P: MerkleTreeHash> {
    perm: P,
}

impl<P: MerkleTreeHash> MerkleTree<P> {
    pub fn new(perm: P) -> Self {
        MerkleTree { perm }
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

    pub fn accumulate(&mut self, set: &[F]) -> F {
        let set_size = set.len();
        let mut bound = Self::round_up_pow_n(set_size, 2);
        loop {
            if bound >= 2 {
                break;
            }
            bound *= 2;
        }
        let mut nodes: Vec<F> = Vec::with_capacity(bound);
        for s in set {
            nodes.push(s.to_owned());
        }
        // pad
        for _ in nodes.len()..bound {
            nodes.push(nodes[set_size - 1].to_owned());
        }

        let mut lv = 0;
        while nodes.len() > 1 {
            let new_len = nodes.len() / 2;
            let mut new_nodes: Vec<F> = Vec::with_capacity(new_len);
            for i in (0..nodes.len()).step_by(2) {
                let inp = [&nodes[i], &nodes[i + 1]];
                let dig = self.perm.compress(lv, &inp);
                new_nodes.push(dig);
            }
            lv += 1;
            nodes = new_nodes;
        }
        nodes[0].to_owned()
    }
}
