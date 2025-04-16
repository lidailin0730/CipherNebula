use super::gmimc_params::GmimcParams;
use crate::fields::goldilocks::FpGoldiLocks;

use lazy_static::lazy_static;
use std::sync::Arc;

type Scalar = FpGoldiLocks;

lazy_static! {
    // Number of rounds:
    // max(2 + 2 * (t + t^2), ceil(2 * log_d(p)) + 2 * t)
    pub static ref GMIMC_GOLDILOCKS_8_PARAMS: Arc<GmimcParams<Scalar>> =
        Arc::new(GmimcParams::new(8, 7, 146));
    pub static ref GMIMC_GOLDILOCKS_12_PARAMS: Arc<GmimcParams<Scalar>> =
        Arc::new(GmimcParams::new(12, 7, 314));
    pub static ref GMIMC_GOLDILOCKS_16_PARAMS: Arc<GmimcParams<Scalar>> =
        Arc::new(GmimcParams::new(16, 7, 546));
    pub static ref GMIMC_GOLDILOCKS_20_PARAMS: Arc<GmimcParams<Scalar>> =
        Arc::new(GmimcParams::new(20, 7, 842));
}
