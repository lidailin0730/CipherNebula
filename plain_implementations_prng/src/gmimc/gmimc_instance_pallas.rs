use super::gmimc_params::GmimcParams;
use crate::fields::pallas::FpPallas;

use lazy_static::lazy_static;
use std::sync::Arc;

type Scalar = FpPallas;

lazy_static! {
    // Number of rounds:
    // max(2 + 2 * (t + t^2), ceil(2 * log_d(p)) + 2 * t)
    pub static ref GMIMC_PALLAS_3_PARAMS: Arc<GmimcParams<Scalar>> =
        Arc::new(GmimcParams::new(3, 5, 226));
    pub static ref GMIMC_PALLAS_4_PARAMS: Arc<GmimcParams<Scalar>> =
        Arc::new(GmimcParams::new(4, 5, 228));
    pub static ref GMIMC_PALLAS_5_PARAMS: Arc<GmimcParams<Scalar>> =
        Arc::new(GmimcParams::new(5, 5, 230));
    pub static ref GMIMC_PALLAS_8_PARAMS: Arc<GmimcParams<Scalar>> =
        Arc::new(GmimcParams::new(8, 5, 236));
    pub static ref GMIMC_PALLAS_9_PARAMS: Arc<GmimcParams<Scalar>> =
        Arc::new(GmimcParams::new(9, 5, 238));
    pub static ref GMIMC_PALLAS_12_PARAMS: Arc<GmimcParams<Scalar>> =
        Arc::new(GmimcParams::new(12, 5, 314));
    pub static ref GMIMC_PALLAS_16_PARAMS: Arc<GmimcParams<Scalar>> =
        Arc::new(GmimcParams::new(16, 5, 546));
    pub static ref GMIMC_PALLAS_20_PARAMS: Arc<GmimcParams<Scalar>> =
        Arc::new(GmimcParams::new(20, 5, 842));
    pub static ref GMIMC_PALLAS_24_PARAMS: Arc<GmimcParams<Scalar>> =
        Arc::new(GmimcParams::new(24, 5, 1202));
}
