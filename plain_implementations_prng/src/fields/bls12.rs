use ark_ff::fields::{Fp256, MontBackend, MontConfig};
use std::convert::TryInto;

#[derive(MontConfig)]
#[modulus = "52435875175126190479447740508185965837690552500527637822603658699938581184513"]
#[generator = "7"]
pub struct FqConfig;
pub type FpBLS12 = Fp256<MontBackend<FqConfig, 4>>;