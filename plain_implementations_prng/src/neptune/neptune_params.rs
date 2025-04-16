use ark_ff::PrimeField;

use crate::fields::utils;

#[derive(Clone, Debug)]
pub struct NeptuneParams<S: PrimeField> {
    pub(crate) t: usize, // statesize
    pub(crate) d: usize, // sbox degree
    pub(crate) rounds_f_beginning: usize,
    pub(crate) rounds_p: usize,
    #[allow(dead_code)]
    pub(crate) rounds_f_end: usize,
    pub(crate) rounds: usize,
    pub(crate) round_constants: Vec<Vec<S>>,
    pub(crate) m_e: Vec<Vec<S>>, // external matrix
    pub(crate) mu: Vec<S>,       // diagonal of internal matrix
    pub(crate) abc: [S; 3],      // alpha, beta, gamma
    #[allow(dead_code)]
    pub(crate) a_: [S; 3], // alpha^2, 3*alpha, 4*alpha
}

impl<S: PrimeField> NeptuneParams<S> {
    pub const INIT_SHAKE: &'static str = "Neptune";

    pub fn new(t: usize, d: usize, rounds_f: usize, rounds_p: usize) -> Self {
        assert!(d == 3 || d == 5 || d == 7);
        assert_eq!(rounds_f % 2, 0);
        assert_eq!(t % 2, 0);

        let r = rounds_f / 2;
        let rounds = rounds_f + rounds_p;

        // let mut shake = Self::init_shake();
        let round_constants = Self::instantiate_rc(t, rounds);
        let m_e = Self::instantiate_external_matrix(t);
        let mu = Self::instantiate_mu(t);
        let abc = Self::instantiate_abc();

        // precomputations for more efficient neptune implementation
        let mut a_ = [abc[0]; 3];
        a_[0].square_in_place();
        a_[1].double_in_place();
        a_[2] = a_[1];
        a_[1].add_assign(&abc[0]);
        a_[2].double_in_place();

        NeptuneParams {
            t,
            d,
            rounds_f_beginning: r,
            rounds_p,
            rounds_f_end: r,
            rounds,
            round_constants,
            m_e,
            mu,
            abc,
            a_,
        }
    }

    // fn init_shake() -> XofReaderCoreWrapper<Shake128ReaderCore> {
    //     let mut shake = Shake128::default();
    //     shake.update(Self::INIT_SHAKE.as_bytes());
    //     for i in S::char().as_ref() {
    //         shake.update(&u64::to_le_bytes(*i));
    //     }
    //     shake.finalize_xof()
    // }

    fn instantiate_rc(t: usize, rounds: usize) -> Vec<Vec<S>> {
        (0..rounds)
            .map(|_| {
                (0..t)
                    .map(|_| utils::random_scalar())
                    .collect()
            })
            .collect()
    }

    fn instantiate_abc() -> [S; 3] {
        let mut abc = [S::one(); 3];
        abc[2] = utils::random_scalar();
        abc
    }

    fn instantiate_mu(t: usize) -> Vec<S> {
        // TODO adapt for real instantiation :)
        (0..t)
            .map(|_| {
                let mut tmp = utils::random_scalar_without_0::<S>();
                tmp.sub_assign(&S::one()); // For faster impl
                tmp
            })
            .collect()
    }

    fn instantiate_external_matrix(t: usize) -> Vec<Vec<S>> {
        let t_ = t >> 1;
        let mut mat = vec![vec![S::zero(); t]; t];

        let m_: Vec<Vec<S>>; // M' matrix
        let m__: Vec<Vec<S>>; // M'' matrix

        if t == 4 {
            m_ = Self::circ_mat(&[S::from(2 as u64), S::one()]);
            m__ = Self::circ_mat(&[S::one(), S::from(2 as u64)]);
        } else if t == 8 {
            m_ = Self::circ_mat(&[
                S::from(3 as u64),
                S::from(2 as u64),
                S::from(1 as u64),
                S::from(1 as u64),
            ]);
            m__ = Self::circ_mat(&[
                S::from(1 as u64),
                S::from(1 as u64),
                S::from(2 as u64),
                S::from(3 as u64),
            ]);
        } else {
            // TODO adapt for real instantiation :)
            m_ = (0..t_)
                .map(|_| {
                    (0..t_)
                        .map(|_| utils::random_scalar())
                        .collect()
                })
                .collect();
            m__ = (0..t_)
                .map(|_| {
                    (0..t_)
                        .map(|_| utils::random_scalar())
                        .collect()
                })
                .collect();
        }

        // M' matrix
        for row in 0..t_ {
            for col in 0..t_ {
                mat[2 * row][2 * col] = m_[row][col];
            }
        }

        // M'' matrix
        for row in 0..t_ {
            for col in 0..t_ {
                mat[2 * row + 1][2 * col + 1] = m__[row][col];
            }
        }
        mat
    }

    fn circ_mat(row: &[S]) -> Vec<Vec<S>> {
        let t = row.len();
        let mut mat: Vec<Vec<S>> = Vec::with_capacity(t);
        let mut rot = row.to_owned();
        mat.push(rot.clone());
        for _ in 1..t {
            rot.rotate_right(1);
            mat.push(rot.clone());
        }
        mat
    }
}
