use crate::merkle_tree::merkle_tree_fp::MerkleTreeHash;

use super::neptune_params::NeptuneParams;
use ark_ff::PrimeField;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct Neptune<S: PrimeField> {
    pub(crate) params: Arc<NeptuneParams<S>>,
}

impl<S: PrimeField> Neptune<S> {
    pub fn new(params: &Arc<NeptuneParams<S>>) -> Self {
        Neptune {
            params: Arc::clone(params),
        }
    }

    pub fn get_t(&self) -> usize {
        self.params.t
    }

    fn external_round(&self, input: &[S], r: usize) -> Vec<S> {
        let output = self.external_sbox(input);
        let output = self.external_matmul(&output);
        self.add_rc(&output, &self.params.round_constants[r])
    }

    fn internal_round(&self, input: &[S], r: usize) -> Vec<S> {
        let output = self.internal_sbox(input);
        let output = self.internal_matmul(&output);
        self.add_rc(&output, &self.params.round_constants[r])
    }

    fn add_rc(&self, input: &[S], rc: &[S]) -> Vec<S> {
        input
            .iter()
            .zip(rc.iter())
            .map(|(a, b)| {
                let mut r = *a;
                r.add_assign(b);
                r
            })
            .collect()
    }

    fn sbox_d(&self, input: &S) -> S {
        let mut input2 = *input;
        input2.square_in_place();

        match self.params.d {
            3 => {
                let mut out = input2;
                out.mul_assign(input);
                out
            }
            5 => {
                let mut out = input2;
                out.square_in_place();
                out.mul_assign(input);
                out
            }
            7 => {
                let mut out = input2;
                out.square_in_place();
                out.mul_assign(&input2);
                out.mul_assign(input);
                out
            }
            _ => {
                panic!();
            }
        }
    }

    fn external_sbox_prime(&self, x1: &S, x2: &S) -> (S, S) {
        let mut zi = x1.to_owned();
        zi.sub_assign(x2);
        let mut zib = zi;
        zib.square_in_place();
        // zib.mul_assign(&self.params.abc[1]); // beta = 1

        // first terms
        let mut sum = x1.to_owned();
        sum.add_assign(x2);
        let mut y1 = sum.to_owned();
        let mut y2 = sum.to_owned();
        y1.add_assign(x1);
        y2.add_assign(x2);
        y2.add_assign(x2);
        // y1.mul_assign(&self.params.a_[0]); // alpha = 1
        // y2.mul_assign(&self.params.a_[0]); // alpha = 1

        // middle terms
        let mut tmp1 = zib.to_owned();
        tmp1.double_in_place();
        let mut tmp2 = tmp1.to_owned();
        tmp1.add_assign(&zib);
        tmp2.double_in_place();
        // tmp1.mul_assign(&self.params.a_[1]); // done with additions, since alpha = beta = 1
        // tmp2.mul_assign(&self.params.a_[2]); // done with additions, since alpha = beta = 1
        y1.add_assign(&tmp1);
        y2.add_assign(&tmp2);

        // third terms
        let mut tmp = zi.to_owned();
        tmp.sub_assign(x2);
        // tmp.mul_assign(&self.params.abc[0]); // alpha = 1
        tmp.sub_assign(&zib);
        tmp.add_assign(&self.params.abc[2]);
        tmp.square_in_place();
        // tmp.mul_assign(&self.params.abc[1]); // beta = 1
        y1.add_assign(&tmp);
        y2.add_assign(&tmp);

        (y1, y2)
    }

    fn external_sbox(&self, input: &[S]) -> Vec<S> {
        let t = input.len();
        let t_ = t >> 1;
        let mut output = vec![S::zero(); t];
        for i in 0..t_ {
            let out = self.external_sbox_prime(&input[2 * i], &input[2 * i + 1]);
            output[2 * i] = out.0;
            output[2 * i + 1] = out.1;
        }
        output
    }

    fn internal_sbox(&self, input: &[S]) -> Vec<S> {
        let mut output = input.to_owned();
        output[0] = self.sbox_d(&input[0]);
        output
    }

    fn external_matmul_4(input: &[S]) -> Vec<S> {
        let mut output = input.to_owned();
        output.swap(1, 3);

        let mut sum1 = input[0].to_owned();
        sum1.add_assign(&input[2]);
        let mut sum2 = input[1].to_owned();
        sum2.add_assign(&input[3]);

        output[0].add_assign(&sum1);
        output[1].add_assign(&sum2);
        output[2].add_assign(&sum1);
        output[3].add_assign(&sum2);

        output
    }

    fn external_matmul_8(input: &[S]) -> Vec<S> {
        // multiplication by circ(3 2 1 1) is equal to state + state + rot(state) + sum(state)
        let mut output = input.to_owned();
        output.swap(1, 7);
        output.swap(3, 5);

        let mut sum1 = input[0].to_owned();
        let mut sum2 = input[1].to_owned();

        input
            .iter()
            .step_by(2)
            .skip(1)
            .for_each(|el| sum1.add_assign(el));
        input
            .iter()
            .skip(1)
            .step_by(2)
            .skip(1)
            .for_each(|el| sum2.add_assign(el));

        let mut output_rot = output.to_owned();
        output_rot.rotate_left(2);

        for ((i, el), rot) in output.iter_mut().enumerate().zip(output_rot.iter()) {
            el.double_in_place();
            el.add_assign(rot);
            if i & 1 == 0 {
                el.add_assign(&sum1);
            } else {
                el.add_assign(&sum2);
            }
        }

        output.swap(3, 7);
        output
    }

    fn external_matmul(&self, input: &[S]) -> Vec<S> {
        let t = self.params.t;

        if t == 4 {
            return Self::external_matmul_4(input);
        } else if t == 8 {
            return Self::external_matmul_8(input);
        }

        let mut out = vec![S::zero(); t];
        let t_ = t >> 1;
        for row in 0..t_ {
            for col in 0..t_ {
                // even rows
                let mut tmp_e = self.params.m_e[2 * row][2 * col];
                tmp_e.mul_assign(&input[2 * col]);
                out[2 * row].add_assign(&tmp_e);

                // odd rows
                let mut tmp_o = self.params.m_e[2 * row + 1][2 * col + 1];
                tmp_o.mul_assign(&input[2 * col + 1]);
                out[2 * row + 1].add_assign(&tmp_o);
            }
        }
        out
    }

    fn internal_matmul(&self, input: &[S]) -> Vec<S> {
        let mut out = input.to_owned();

        let mut sum = input[0];
        input.iter().skip(1).for_each(|el| sum.add_assign(el));

        for (o, mu) in out.iter_mut().zip(self.params.mu.iter()) {
            o.mul_assign(mu);
            // o.sub_assign(input[row]); // Already done in parameter creation
            o.add_assign(&sum);
        }
        out
    }

    pub fn permutation(&self, input: &[S]) -> Vec<S> {
        let t = self.params.t;
        assert_eq!(input.len(), t);

        // inital matmul
        let mut current_state = self.external_matmul(input);

        for r in 0..self.params.rounds_f_beginning {
            current_state = self.external_round(&current_state, r);
        }
        let p_end = self.params.rounds_f_beginning + self.params.rounds_p;
        for r in self.params.rounds_f_beginning..p_end {
            current_state = self.internal_round(&current_state, r);
        }
        for r in p_end..self.params.rounds {
            current_state = self.external_round(&current_state, r);
        }

        current_state
    }
}

impl<S: PrimeField> MerkleTreeHash<S> for Neptune<S> {
    fn compress(&self, input: &[&S]) -> S {
        self.permutation(&[
            input[0].to_owned(),
            input[1].to_owned(),
            S::zero(),
            S::zero(),
        ])[0]
    }
}

#[cfg(test)]
mod neptune_tests_bls12 {
    use super::*;
    use crate::{fields::{bls12::FpBLS12, utils}};
    use crate::neptune::neptune_instances::{
        NEPTUNE_BLS_4_PARAMS,
        NEPTUNE_BLS_8_PARAMS,
    };
    type Scalar = FpBLS12;

    static TESTRUNS: usize = 5;

    fn matmul(input: &[Scalar], mat: &[Vec<Scalar>]) -> Vec<Scalar> {
        let t = mat.len();
        debug_assert!(t == input.len());
        let mut out = vec![Scalar::from(0); t];
        for row in 0..t {
            for (col, inp) in input.iter().enumerate().take(t) {
                let mut tmp: Scalar = mat[row][col];
                tmp *= inp;
                out[row] += tmp;
            }
        }
        out
    }

    fn build_mi(neptune_params: &Arc<NeptuneParams<Scalar>>) -> Vec<Vec<Scalar>> {
        let t = neptune_params.t;
        let mut mi = vec![vec![Scalar::from(1); t]; t];
        for (i, matrow) in mi.iter_mut().enumerate().take(t) {
            matrow[i] = neptune_params.mu[i];
            matrow[i] += Scalar::from(1); // Compensate for subtraction in parameter creation
        }
        mi
    }

    fn matmul_equalities(t: usize) {
        let neptune_params = Arc::new(NeptuneParams::<Scalar>::new(t, 3, 2, 1));
        let neptune = Neptune::new(&neptune_params);
        let t = neptune.params.t;

        // check external matrix
        let me = &neptune_params.m_e;
        for (row, matrow) in me.iter().enumerate().take(t) {
            for (col, matrowcol) in matrow.iter().enumerate().take(t) {
                if (row + col) % 2 == 0 {
                    assert!(*matrowcol != Scalar::from(0));
                } else {
                    assert_eq!(*matrowcol, Scalar::from(0));
                }
            }
        }

        let mi = build_mi(&neptune_params);
        for _ in 0..TESTRUNS {
            let input: Vec<Scalar> = (0..t).map(|_| utils::random_scalar()).collect();
            let external1 = neptune.external_matmul(&input);
            let external2 = matmul(&input, me);
            assert_eq!(external1, external2);

            let internal1 = neptune.internal_matmul(&input);
            let internal2 = matmul(&input, &mi);
            assert_eq!(internal1, internal2);
        }
    }

    #[test]
    fn matmul_equalities_4() {
        matmul_equalities(4);
    }

    #[test]
    fn matmul_equalities_6() {
        matmul_equalities(6);
    }

    #[test]
    fn matmul_equalities_8() {
        matmul_equalities(8);
    }

    #[test]
    fn matmul_equalities_10() {
        matmul_equalities(10);
    }

    #[test]
    fn matmul_equalities_60() {
        matmul_equalities(60);
    }

    #[test]
    fn consistent_perm() {
        let instances = vec![
            Neptune::new(&NEPTUNE_BLS_4_PARAMS),
            Neptune::new(&NEPTUNE_BLS_8_PARAMS),
        ];
        for instance in instances {
            let t = instance.params.t;
            for _ in 0..TESTRUNS {
                let input1: Vec<Scalar> = (0..t).map(|_| utils::random_scalar()).collect();

                let mut input2: Vec<Scalar>;
                loop {
                    input2 = (0..t).map(|_| utils::random_scalar()).collect();
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
}

#[cfg(test)]
mod neptune_tests_bn256 {
    use super::*;
    use crate::{
        fields::{bn256::FpBN256, utils},
        neptune::neptune_instances::NEPTUNE_BN_PARAMS,
    };
    type Scalar = FpBN256;

    static TESTRUNS: usize = 5;

    fn matmul(input: &[Scalar], mat: &[Vec<Scalar>]) -> Vec<Scalar> {
        let t = mat.len();
        debug_assert!(t == input.len());
        let mut out = vec![Scalar::from(0); t];
        for row in 0..t {
            for (col, inp) in input.iter().enumerate().take(t) {
                let mut tmp = mat[row][col];
                tmp *= inp;
                out[row] += tmp;
            }
        }
        out
    }

    fn build_mi(neptune_params: &Arc<NeptuneParams<Scalar>>) -> Vec<Vec<Scalar>> {
        let t = neptune_params.t;
        let mut mi = vec![vec![Scalar::from(1); t]; t];
        for (i, matrow) in mi.iter_mut().enumerate().take(t) {
            matrow[i] = neptune_params.mu[i];
            matrow[i] += Scalar::from(1); // Compensate for subtraction in parameter creation
        }
        mi
    }

    fn matmul_equalities(t: usize) {
        let neptune_params = Arc::new(NeptuneParams::<Scalar>::new(t, 3, 2, 1));
        let neptune = Neptune::new(&neptune_params);
        let t = neptune.params.t;

        // check external matrix
        let me = &neptune_params.m_e;
        for (row, matrow) in me.iter().enumerate().take(t) {
            for (col, matrowcol) in matrow.iter().enumerate().take(t) {
                if (row + col) % 2 == 0 {
                    assert!(*matrowcol != Scalar::from(0));
                } else {
                    assert_eq!(*matrowcol, Scalar::from(0));
                }
            }
        }

        let mi = build_mi(&neptune_params);
        for _ in 0..TESTRUNS {
            let input: Vec<Scalar> = (0..t).map(|_| utils::random_scalar()).collect();
            let external1 = neptune.external_matmul(&input);
            let external2 = matmul(&input, me);
            assert_eq!(external1, external2);

            let internal1 = neptune.internal_matmul(&input);
            let internal2 = matmul(&input, &mi);
            assert_eq!(internal1, internal2);
        }
    }

    #[test]
    fn matmul_equalities_4() {
        matmul_equalities(4);
    }

    #[test]
    fn matmul_equalities_6() {
        matmul_equalities(6);
    }

    #[test]
    fn matmul_equalities_8() {
        matmul_equalities(8);
    }

    #[test]
    fn matmul_equalities_10() {
        matmul_equalities(10);
    }

    #[test]
    fn matmul_equalities_60() {
        matmul_equalities(60);
    }

    #[test]
    fn consistent_perm() {
        let neptune = Neptune::new(&NEPTUNE_BN_PARAMS);
        let t = neptune.params.t;
        for _ in 0..TESTRUNS {
            let input1: Vec<Scalar> = (0..t).map(|_| utils::random_scalar()).collect();

            let mut input2: Vec<Scalar>;
            loop {
                input2 = (0..t).map(|_| utils::random_scalar()).collect();
                if input1 != input2 {
                    break;
                }
            }

            let perm1 = neptune.permutation(&input1);
            let perm2 = neptune.permutation(&input1);
            let perm3 = neptune.permutation(&input2);
            assert_eq!(perm1, perm2);
            assert_ne!(perm1, perm3);
        }
    }
}

#[cfg(test)]
mod neptune_tests_goldilocks {
    use super::*;
    use crate::{fields::{goldilocks::FpGoldiLocks, utils}};
    use crate::neptune::neptune_instances::{
        NEPTUNE_GOLDILOCKS_8_PARAMS,
        NEPTUNE_GOLDILOCKS_12_PARAMS,
        NEPTUNE_GOLDILOCKS_16_PARAMS,
        NEPTUNE_GOLDILOCKS_20_PARAMS,
    };
    type Scalar = FpGoldiLocks;

    static TESTRUNS: usize = 5;

    fn matmul(input: &[Scalar], mat: &[Vec<Scalar>]) -> Vec<Scalar> {
        let t = mat.len();
        debug_assert!(t == input.len());
        let mut out = vec![Scalar::from(0); t];
        for row in 0..t {
            for (col, inp) in input.iter().enumerate().take(t) {
                let mut tmp = mat[row][col];
                tmp *= inp;
                out[row] += tmp;
            }
        }
        out
    }

    fn build_mi(neptune_params: &Arc<NeptuneParams<Scalar>>) -> Vec<Vec<Scalar>> {
        let t = neptune_params.t;
        let mut mi = vec![vec![Scalar::from(1); t]; t];
        for (i, matrow) in mi.iter_mut().enumerate().take(t) {
            matrow[i] = neptune_params.mu[i];
            matrow[i] += Scalar::from(1); // Compensate for subtraction in parameter creation
        }
        mi
    }

    fn matmul_equalities(t: usize) {
        let neptune_params = Arc::new(NeptuneParams::<Scalar>::new(t, 3, 2, 1));
        let neptune = Neptune::new(&neptune_params);
        let t = neptune.params.t;

        // check external matrix
        let me = &neptune_params.m_e;
        for (row, matrow) in me.iter().enumerate().take(t) {
            for (col, matrowcol) in matrow.iter().enumerate().take(t) {
                if (row + col) % 2 == 0 {
                    assert!(*matrowcol != Scalar::from(0));
                } else {
                    assert_eq!(*matrowcol, Scalar::from(0));
                }
            }
        }

        let mi = build_mi(&neptune_params);
        for _ in 0..TESTRUNS {
            let input: Vec<Scalar> = (0..t).map(|_| utils::random_scalar()).collect();
            let external1 = neptune.external_matmul(&input);
            let external2 = matmul(&input, me);
            assert_eq!(external1, external2);

            let internal1 = neptune.internal_matmul(&input);
            let internal2 = matmul(&input, &mi);
            assert_eq!(internal1, internal2);
        }
    }

    #[test]
    fn matmul_equalities_4() {
        matmul_equalities(4);
    }

    #[test]
    fn matmul_equalities_6() {
        matmul_equalities(6);
    }

    #[test]
    fn matmul_equalities_8() {
        matmul_equalities(8);
    }

    #[test]
    fn matmul_equalities_10() {
        matmul_equalities(10);
    }

    #[test]
    fn matmul_equalities_60() {
        matmul_equalities(60);
    }

    #[test]
    fn consistent_perm() {
        let instances = vec![
            Neptune::new(&NEPTUNE_GOLDILOCKS_8_PARAMS),
            Neptune::new(&NEPTUNE_GOLDILOCKS_12_PARAMS),
            Neptune::new(&NEPTUNE_GOLDILOCKS_16_PARAMS),
            Neptune::new(&NEPTUNE_GOLDILOCKS_20_PARAMS),
        ];
        for instance in instances {
            let t = instance.params.t;
            for _ in 0..TESTRUNS {
                let input1: Vec<Scalar> = (0..t).map(|_| utils::random_scalar()).collect();

                let mut input2: Vec<Scalar>;
                loop {
                    input2 = (0..t).map(|_| utils::random_scalar()).collect();
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
}

#[cfg(test)]
mod neptune_tests_babybear {
    use super::*;
    use crate::{
        fields::{babybear::FpBabyBear, utils},
        neptune::neptune_instances::NEPTUNE_BABYBEAR_16_PARAMS,
        neptune::neptune_instances::NEPTUNE_BABYBEAR_24_PARAMS,
    };
    type Scalar = FpBabyBear;

    static TESTRUNS: usize = 5;

    fn matmul(input: &[Scalar], mat: &[Vec<Scalar>]) -> Vec<Scalar> {
        let t = mat.len();
        debug_assert!(t == input.len());
        let mut out = vec![Scalar::from(0); t];
        for row in 0..t {
            for (col, inp) in input.iter().enumerate().take(t) {
                let mut tmp = mat[row][col];
                tmp *= inp;
                out[row] += tmp;
            }
        }
        out
    }

    fn build_mi(neptune_params: &Arc<NeptuneParams<Scalar>>) -> Vec<Vec<Scalar>> {
        let t = neptune_params.t;
        let mut mi = vec![vec![Scalar::from(1); t]; t];
        for (i, matrow) in mi.iter_mut().enumerate().take(t) {
            matrow[i] = neptune_params.mu[i];
            matrow[i] += Scalar::from(1); // Compensate for subtraction in parameter creation
        }
        mi
    }

    fn matmul_equalities(t: usize) {
        let neptune_params = Arc::new(NeptuneParams::<Scalar>::new(t, 3, 2, 1));
        let neptune = Neptune::new(&neptune_params);
        let t = neptune.params.t;

        // check external matrix
        let me = &neptune_params.m_e;
        for (row, matrow) in me.iter().enumerate().take(t) {
            for (col, matrowcol) in matrow.iter().enumerate().take(t) {
                if (row + col) % 2 == 0 {
                    assert!(*matrowcol != Scalar::from(0));
                } else {
                    assert_eq!(*matrowcol, Scalar::from(0));
                }
            }
        }

        let mi = build_mi(&neptune_params);
        for _ in 0..TESTRUNS {
            let input: Vec<Scalar> = (0..t).map(|_| utils::random_scalar()).collect();
            let external1 = neptune.external_matmul(&input);
            let external2 = matmul(&input, me);
            assert_eq!(external1, external2);

            let internal1 = neptune.internal_matmul(&input);
            let internal2 = matmul(&input, &mi);
            assert_eq!(internal1, internal2);
        }
    }

    #[test]
    fn matmul_equalities_4() {
        matmul_equalities(4);
    }

    #[test]
    fn matmul_equalities_6() {
        matmul_equalities(6);
    }

    #[test]
    fn matmul_equalities_8() {
        matmul_equalities(8);
    }

    #[test]
    fn matmul_equalities_10() {
        matmul_equalities(10);
    }

    #[test]
    fn matmul_equalities_60() {
        matmul_equalities(60);
    }

    #[test]
    fn consistent_perm() {
        let instances = vec![
            Neptune::new(&NEPTUNE_BABYBEAR_16_PARAMS),
            Neptune::new(&NEPTUNE_BABYBEAR_24_PARAMS),
        ];
        for instance in instances {
            let t = instance.params.t;
            for _ in 0..TESTRUNS {
                let input1: Vec<Scalar> = (0..t).map(|_| utils::random_scalar()).collect();

                let mut input2: Vec<Scalar>;
                loop {
                    input2 = (0..t).map(|_| utils::random_scalar()).collect();
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
}
