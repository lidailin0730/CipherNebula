use ark_ff::fields::{Fp64, MontBackend, MontConfig};
use std::convert::TryInto;

#[derive(MontConfig)]
#[modulus = "2013265921"]
#[generator = "31"]
pub struct FqConfig;
pub type FpBabyBear = Fp64<MontBackend<FqConfig, 1>>;