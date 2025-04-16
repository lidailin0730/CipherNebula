use lazy_static::lazy_static;
use std::sync::Arc;

use crate::{
    fields::{bls12::FpBLS12, bn256::FpBN256, pallas::FpPallas, vesta::FpVesta, goldilocks::FpGoldiLocks, babybear::FpBabyBear},
    neptune::neptune_params::NeptuneParams,
};

lazy_static! {
    // Number of partial rounds:
    // ceil(1.125 * ceil(log_d(2) * (min(kappa, log_2(p)) - 6) + 3 + t + log_d(t)))
    // BN256
    pub static ref NEPTUNE_BN_PARAMS: Arc<NeptuneParams<FpBN256>> = Arc::new(NeptuneParams::new(4, 5, 6, 68));
    // BLS12
    pub static ref NEPTUNE_BLS_4_PARAMS: Arc<NeptuneParams<FpBLS12>> = Arc::new(NeptuneParams::new(4, 5, 6, 69));
    pub static ref NEPTUNE_BLS_8_PARAMS: Arc<NeptuneParams<FpBLS12>> = Arc::new(NeptuneParams::new(8, 5, 6, 74));
    // Goldilocks
    pub static ref NEPTUNE_GOLDILOCKS_8_PARAMS: Arc<NeptuneParams<FpGoldiLocks>> = Arc::new(NeptuneParams::new(8, 7, 6, 38));
    pub static ref NEPTUNE_GOLDILOCKS_12_PARAMS: Arc<NeptuneParams<FpGoldiLocks>> = Arc::new(NeptuneParams::new(12, 7, 6, 42));
    pub static ref NEPTUNE_GOLDILOCKS_16_PARAMS: Arc<NeptuneParams<FpGoldiLocks>> = Arc::new(NeptuneParams::new(16, 7, 6, 48));
    pub static ref NEPTUNE_GOLDILOCKS_20_PARAMS: Arc<NeptuneParams<FpGoldiLocks>> = Arc::new(NeptuneParams::new(20, 7, 6, 52));
    // BabyBear
    pub static ref NEPTUNE_BABYBEAR_16_PARAMS: Arc<NeptuneParams<FpBabyBear>> = Arc::new(NeptuneParams::new(16, 7, 6, 34));
    pub static ref NEPTUNE_BABYBEAR_24_PARAMS: Arc<NeptuneParams<FpBabyBear>> = Arc::new(NeptuneParams::new(24, 7, 6, 43));
    // Pallas
    pub static ref NEPTUNE_PALLAS_4_PARAMS: Arc<NeptuneParams<FpPallas>> = Arc::new(NeptuneParams::new(4, 5, 6, 69));
    pub static ref NEPTUNE_PALLAS_8_PARAMS: Arc<NeptuneParams<FpPallas>> = Arc::new(NeptuneParams::new(8, 5, 6, 74));
    // Vesta
    pub static ref NEPTUNE_VESTA_PARAMS: Arc<NeptuneParams<FpVesta>> = Arc::new(NeptuneParams::new(4, 5, 6, 68));
}