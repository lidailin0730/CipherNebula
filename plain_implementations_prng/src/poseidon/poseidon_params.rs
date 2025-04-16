use ark_ff::PrimeField;

use crate::utils;

#[derive(Clone, Debug)]
pub struct PoseidonParams<S: PrimeField> {
    pub(crate) t: usize, // statesize
    pub(crate) d: usize, // sbox degree
    pub(crate) rounds_f_beginning: usize,
    pub(crate) rounds_p: usize,
    #[allow(dead_code)]
    pub(crate) rounds_f_end: usize,
    pub(crate) rounds: usize,
    pub(crate) mds: Vec<Vec<S>>,
    pub(crate) round_constants: Vec<Vec<S>>,
    pub(crate) opt_round_constants: Vec<Vec<S>>, // optimized
    pub(crate) w_hat: Vec<Vec<S>>,               // optimized
    pub(crate) v: Vec<Vec<S>>,                   // optimized
    pub(crate) m_i: Vec<Vec<S>>,                 // optimized
}

impl<S: PrimeField> PoseidonParams<S> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        t: usize,
        d: usize,
        rounds_f: usize,
        rounds_p: usize,
        mds: &[Vec<S>],
        round_constants: &[Vec<S>],
    ) -> Self {
        assert!(d == 3 || d == 5 || d == 7);
        assert_eq!(mds.len(), t);
        assert_eq!(rounds_f % 2, 0);
        let r = rounds_f / 2;
        let rounds = rounds_f + rounds_p;

        let (m_i_, v_, w_hat_) = Self::equivalent_matrices(mds, t, rounds_p);
        let opt_round_constants_ = Self::equivalent_round_constants(round_constants, mds, r, rounds_p);

        PoseidonParams {
            t,
            d,
            rounds_f_beginning: r,
            rounds_p,
            rounds_f_end: r,
            rounds,
            mds: mds.to_owned(),
            round_constants: round_constants.to_owned(),
            opt_round_constants: opt_round_constants_,
            w_hat: w_hat_,
            v: v_,
            m_i: m_i_,
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn equivalent_matrices(
        mds: &[Vec<S>],
        t: usize,
        rounds_p: usize,
    ) -> (Vec<Vec<S>>, Vec<Vec<S>>, Vec<Vec<S>>) {
        let mut w_hat = Vec::with_capacity(rounds_p);
        let mut v = Vec::with_capacity(rounds_p);
        let mut m_i = vec![vec![S::zero(); t]; t];

        let mds_ = utils::mat_transpose(mds);
        let mut m_mul = mds_.clone();

        for _ in 0..rounds_p {
            // calc m_hat, w and v
            let mut m_hat = vec![vec![S::zero(); t - 1]; t - 1];
            let mut w = vec![S::zero(); t - 1];
            let mut v_ = vec![S::zero(); t - 1];
            v_[..(t - 1)].clone_from_slice(&m_mul[0][1..t]);
            for row in 1..t {
                for col in 1..t {
                    m_hat[row - 1][col - 1] = m_mul[row][col];
                }
                w[row - 1] = m_mul[row][0];
            }
            // calc_w_hat
            let m_hat_inv = utils::mat_inverse(&m_hat);
            let w_hat_ = Self::mat_vec_mul(&m_hat_inv, &w);

            w_hat.push(w_hat_);
            v.push(v_);

            // update m_i
            m_i = m_mul.clone();
            m_i[0][0] = S::one();
            for i in 1..t {
                m_i[0][i] = S::zero();
                m_i[i][0] = S::zero();
            }
            m_mul = Self::mat_mat_mul(&mds_, &m_i);
        }

        (utils::mat_transpose(&m_i), v, w_hat)
    }

    pub fn equivalent_round_constants(
        round_constants: &[Vec<S>],
        mds: &[Vec<S>],
        rounds_f_beginning: usize,
        rounds_p: usize,
    ) -> Vec<Vec<S>> {
        let mut opt = vec![Vec::new(); rounds_p];
        let mds_inv = utils::mat_inverse(mds);

        let p_end = rounds_f_beginning + rounds_p - 1;
        let mut tmp = round_constants[p_end].clone();
        for i in (0..rounds_p - 1).rev() {
            let inv_cip = Self::mat_vec_mul(&mds_inv, &tmp);
            opt[i + 1] = vec![inv_cip[0]];
            tmp = round_constants[rounds_f_beginning + i].clone();
            for i in 1..inv_cip.len() {
                tmp[i].add_assign(&inv_cip[i]);
            }
        }
        opt[0] = tmp;

        opt
    }

    pub fn mat_vec_mul(mat: &[Vec<S>], input: &[S]) -> Vec<S> {
        let t = mat.len();
        debug_assert!(t == input.len());
        let mut out = vec![S::zero(); t];
        for row in 0..t {
            for (col, inp) in input.iter().enumerate() {
                let mut tmp = mat[row][col];
                tmp.mul_assign(inp);
                out[row].add_assign(&tmp);
            }
        }
        out
    }

    pub fn mat_mat_mul(mat1: &[Vec<S>], mat2: &[Vec<S>]) -> Vec<Vec<S>> {
        let t = mat1.len();
        let mut out = vec![vec![S::zero(); t]; t];
        for row in 0..t {
            for col1 in 0..t {
                for (col2, m2) in mat2.iter().enumerate() {
                    let mut tmp = mat1[row][col2];
                    tmp.mul_assign(&m2[col1]);
                    out[row][col1].add_assign(&tmp);
                }
            }
        }
        out
    }

}
