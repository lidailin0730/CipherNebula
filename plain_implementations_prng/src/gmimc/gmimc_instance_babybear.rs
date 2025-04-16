use super::gmimc_params::GmimcParams;
use crate::fields::babybear::FpBabyBear;

use lazy_static::lazy_static;
use std::sync::Arc;

type Scalar = FpBabyBear;

lazy_static! {
    // Number of rounds:
    // max(2 + 2 * (t + t^2), ceil(2 * log_d(p)) + 2 * t)
    pub static ref GMIMC_BABYBEAR_16_PARAMS: Arc<GmimcParams<Scalar>> =
        Arc::new(GmimcParams::new(16, 7, 546));
    pub static ref GMIMC_BABYBEAR_24_PARAMS: Arc<GmimcParams<Scalar>> =
        Arc::new(GmimcParams::new(24, 7, 1202));
}
