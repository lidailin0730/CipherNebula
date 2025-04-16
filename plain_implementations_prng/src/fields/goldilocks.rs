use ark_ff::fields::{Fp64, MontBackend, MontConfig};
use std::convert::TryInto;

#[derive(MontConfig)]
#[modulus = "18446744069414584321"]
#[generator = "7"]
pub struct FqConfig;
pub type FpGoldiLocks = Fp64<MontBackend<FqConfig, 1>>;