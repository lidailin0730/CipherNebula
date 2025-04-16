use crate::merkle_tree::merkle_tree_fp::MerkleTreeHash;

use std::sync::Arc;

use ark_ff::PrimeField;

use super::gmimc_params::GmimcParams;

#[derive(Clone, Debug)]
pub struct Gmimc<S: PrimeField> {
    pub(crate) params: Arc<GmimcParams<S>>,
}

impl<S: PrimeField> Gmimc<S> {
    pub fn new(params: &Arc<GmimcParams<S>>) -> Self {
        Gmimc {
            params: Arc::clone(params),
        }
    }

    pub fn get_t(&self) -> usize {
        self.params.t
    }

    fn sbox(&self, state_0: &S, round: usize) -> S {
        let mut input = *state_0;
        input.add_assign(&self.params.round_constants[round]);

        let mut input2 = input.to_owned();
        input2.square_in_place();
        match self.params.d {
            3 => {
                let mut out = input2;
                out.mul_assign(&input);
                out
            }
            5 => {
                let mut out = input2;
                out.square_in_place();
                out.mul_assign(&input);
                out
            }
            7 => {
                let mut out = input2;
                out.square_in_place();
                out.mul_assign(&input2);
                out.mul_assign(&input);
                out
            }
            _ => {
                panic!();
            }
        }
    }

    fn round(&self, state: &mut [S], round: usize) {
        let power = self.sbox(&state[0], round);
        state.iter_mut().skip(1).for_each(|f| f.add_assign(&power));
    }

    pub fn permutation(&self, input: &[S]) -> Vec<S> {
        let t = self.params.t;
        // not opt is faster for small t
        if t < 8 {
            return self.permutation_not_opt(input);
        }

        assert_eq!(t, input.len());
        let mut current_state = input.to_owned();
        let mut acc = S::zero();
        let mut acc_queue = vec![S::zero(); t - 1];
        for r in 0..self.params.rounds - 1 {
            let power = self.sbox(&current_state[0], r);
            acc_queue.rotate_right(1);
            acc.sub_assign(&acc_queue[0]);
            acc_queue[0] = power;
            acc.add_assign(&power);

            current_state.rotate_right(1);
            current_state[0].add_assign(&acc);
        }

        // finally without rotation
        let power = self.sbox(&current_state[0], self.params.rounds - 1);
        acc_queue.rotate_right(1);
        acc.sub_assign(&acc_queue[0]);
        acc_queue[0] = power;
        acc.add_assign(&power);
        current_state[t - 1].add_assign(&acc);

        // final adds
        for el in current_state.iter_mut().skip(1).take(t - 2).rev() {
            acc_queue.rotate_right(1);
            acc.sub_assign(&acc_queue[0]);
            el.add_assign(&acc);
        }

        current_state
    }

    pub fn permutation_not_opt(&self, input: &[S]) -> Vec<S> {
        assert_eq!(self.params.t, input.len());
        let mut current_state = input.to_owned();
        for r in 0..self.params.rounds - 1 {
            self.round(&mut current_state, r);
            current_state.rotate_right(1);
        }

        // finally without rotation
        self.round(&mut current_state, self.params.rounds - 1);

        current_state
    }
}

impl<F: PrimeField> MerkleTreeHash<F> for Gmimc<F> {
    fn compress(&self, input: &[&F]) -> F {
        self.permutation(&[input[0].to_owned(), input[1].to_owned(), F::zero()])[0]
    }
}

#[cfg(test)]
mod gmimc_tests_bls12 {
    use super::*;
    use crate::gmimc::gmimc_instance_bls12::GMIMC_BLS_3_PARAMS;
    use crate::fields::{bls12::FpBLS12, utils::random_scalar};

    type Scalar = FpBLS12;

    static TESTRUNS: usize = 5;

    #[test]
    fn consistent_perm() {
        let gmimc = Gmimc::new(&GMIMC_BLS_3_PARAMS);
        let t = gmimc.params.t;
        for _ in 0..TESTRUNS {
            let input1: Vec<Scalar> = (0..t).map(|_| random_scalar()).collect();

            let mut input2: Vec<Scalar>;
            loop {
                input2 = (0..t).map(|_| random_scalar()).collect();
                if input1 != input2 {
                    break;
                }
            }

            let perm1 = gmimc.permutation(&input1);
            let perm2 = gmimc.permutation(&input1);
            let perm3 = gmimc.permutation(&input2);
            assert_eq!(perm1, perm2);
            assert_ne!(perm1, perm3);
        }
    }

    #[test]
    fn opt_equals_not_opt() {
        let gmimc = Gmimc::new(&GMIMC_BLS_3_PARAMS);
        let t = gmimc.params.t;
        for _ in 0..TESTRUNS {
            let input: Vec<Scalar> = (0..t).map(|_| random_scalar()).collect();

            let perm1 = gmimc.permutation(&input);
            let perm2 = gmimc.permutation_not_opt(&input);
            assert_eq!(perm1, perm2);
        }
    }
}

#[cfg(test)]
mod gmimc_tests_bn256 {
    use super::*;
    use crate::gmimc::gmimc_instance_bn256::GMIMC_BN_3_PARAMS;
    use crate::fields::{bn256::FpBN256, utils::random_scalar};

    type Scalar = FpBN256;

    static TESTRUNS: usize = 5;

    #[test]
    fn consistent_perm() {
        let gmimc = Gmimc::new(&GMIMC_BN_3_PARAMS);
        let t = gmimc.params.t;
        for _ in 0..TESTRUNS {
            let input1: Vec<Scalar> = (0..t).map(|_| random_scalar()).collect();

            let mut input2: Vec<Scalar>;
            loop {
                input2 = (0..t).map(|_| random_scalar()).collect();
                if input1 != input2 {
                    break;
                }
            }

            let perm1 = gmimc.permutation(&input1);
            let perm2 = gmimc.permutation(&input1);
            let perm3 = gmimc.permutation(&input2);
            assert_eq!(perm1, perm2);
            assert_ne!(perm1, perm3);
        }
    }

    #[test]
    fn opt_equals_not_opt() {
        let gmimc = Gmimc::new(&GMIMC_BN_3_PARAMS);
        let t = gmimc.params.t;
        for _ in 0..TESTRUNS {
            let input: Vec<Scalar> = (0..t).map(|_| random_scalar()).collect();

            let perm1 = gmimc.permutation(&input);
            let perm2 = gmimc.permutation_not_opt(&input);
            assert_eq!(perm1, perm2);
        }
    }
}

#[cfg(test)]
mod gmimc_tests_goldilocks {
    use super::*;
    use crate::fields::{goldilocks::FpGoldiLocks, utils::random_scalar};
    use crate::gmimc::gmimc_instance_goldilocks::{
        GMIMC_GOLDILOCKS_8_PARAMS,
        GMIMC_GOLDILOCKS_12_PARAMS,
        GMIMC_GOLDILOCKS_16_PARAMS,
        GMIMC_GOLDILOCKS_20_PARAMS,
    };

    type Scalar = FpGoldiLocks;

    static TESTRUNS: usize = 5;

    #[test]
    fn consistent_perm() {
        let instances = vec![
            Gmimc::new(&GMIMC_GOLDILOCKS_8_PARAMS),
            Gmimc::new(&GMIMC_GOLDILOCKS_12_PARAMS),
            Gmimc::new(&GMIMC_GOLDILOCKS_16_PARAMS),
            Gmimc::new(&GMIMC_GOLDILOCKS_20_PARAMS),
        ];
        for instance in instances {
            let t = instance.params.t;
            for _ in 0..TESTRUNS {
                let input1: Vec<Scalar> = (0..t).map(|_| random_scalar()).collect();

                let mut input2: Vec<Scalar>;
                loop {
                    input2 = (0..t).map(|_| random_scalar()).collect();
                    if input1 != input2 {
                        break;
                    }
                }

                let perm1 = instance.permutation(&input1);
                let perm2 = instance.permutation(&input1);
                let perm3 = instance.permutation(&input2);
                assert_eq!(perm1, perm2);
                assert_ne!(perm1, perm3);
            }
        }
    }

    #[test]
    fn opt_equals_not_opt() {
        let instances = vec![
            Gmimc::new(&GMIMC_GOLDILOCKS_8_PARAMS),
            Gmimc::new(&GMIMC_GOLDILOCKS_12_PARAMS),
            Gmimc::new(&GMIMC_GOLDILOCKS_16_PARAMS),
            Gmimc::new(&GMIMC_GOLDILOCKS_20_PARAMS),
        ];
        for instance in instances {
            let t = instance.params.t;
            for _ in 0..TESTRUNS {
                let input: Vec<Scalar> = (0..t).map(|_| random_scalar()).collect();

                let perm1 = instance.permutation(&input);
                let perm2 = instance.permutation_not_opt(&input);
                assert_eq!(perm1, perm2);
            }
        }
    }
}

#[cfg(test)]
mod gmimc_tests_babybear {
    use super::*;
    use crate::gmimc::gmimc_instance_babybear::GMIMC_BABYBEAR_16_PARAMS;
    use crate::gmimc::gmimc_instance_babybear::GMIMC_BABYBEAR_24_PARAMS;
    use crate::fields::{babybear::FpBabyBear, utils::random_scalar};

    type Scalar = FpBabyBear;

    static TESTRUNS: usize = 5;

    #[test]
    fn consistent_perm() {
        let instances = vec![
            Gmimc::new(&GMIMC_BABYBEAR_16_PARAMS),
            Gmimc::new(&GMIMC_BABYBEAR_24_PARAMS),
        ];
        for instance in instances {
            let t = instance.params.t;
            for _ in 0..TESTRUNS {
                let input1: Vec<Scalar> = (0..t).map(|_| random_scalar()).collect();

                let mut input2: Vec<Scalar>;
                loop {
                    input2 = (0..t).map(|_| random_scalar()).collect();
                    if input1 != input2 {
                        break;
                    }
                }

                let perm1 = instance.permutation(&input1);
                let perm2 = instance.permutation(&input1);
                let perm3 = instance.permutation(&input2);
                assert_eq!(perm1, perm2);
                assert_ne!(perm1, perm3);
            }
        }
    }

    #[test]
    fn opt_equals_not_opt() {
        let instances = vec![
            Gmimc::new(&GMIMC_BABYBEAR_16_PARAMS),
            Gmimc::new(&GMIMC_BABYBEAR_24_PARAMS),
        ];
        for instance in instances {
            let t = instance.params.t;
            for _ in 0..TESTRUNS {
                let input: Vec<Scalar> = (0..t).map(|_| random_scalar()).collect();

                let perm1 = instance.permutation(&input);
                let perm2 = instance.permutation_not_opt(&input);
                assert_eq!(perm1, perm2);
            }
        }
    }
}
