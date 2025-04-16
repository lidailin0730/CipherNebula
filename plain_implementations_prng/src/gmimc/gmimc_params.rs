use ark_ff::PrimeField;

use crate::fields::utils;

#[derive(Clone, Debug)]
pub struct GmimcParams<S: PrimeField> {
    pub(crate) t: usize, // statesize
    pub(crate) d: usize, // sbox degree
    pub(crate) rounds: usize,
    pub(crate) round_constants: Vec<S>,
}

impl<S: PrimeField> GmimcParams<S> {
    // pub const INIT_SHAKE: &'static str = "GMiMC";

    pub fn new(t: usize, d: usize, rounds: usize) -> Self {
        assert!(d == 3 || d == 5 || d == 7);
        // let mut shake = Self::init_shake();
        // let round_constants = Self::instantiate_rc(rounds, &mut shake);
        let round_constants = Self::instantiate_rc(rounds);

        GmimcParams {
            t,
            d,
            rounds,
            round_constants,
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

    fn instantiate_rc(rounds: usize) -> Vec<S> {
        (0..rounds)
            .map(|_| utils::random_scalar())
            .collect()
    }

    pub fn get_t(&self) -> usize {
        self.t
    }

    pub fn get_rounds(&self) -> usize {
        self.rounds
    }
}
