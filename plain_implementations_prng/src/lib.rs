//! # zkhash
//!
//! A pure Rust implementation of the ReinforcedConcrete Permutation
#![cfg_attr(feature = "asm", feature(asm))]

pub extern crate ark_ff;

pub mod fields;
pub mod gmimc;
pub mod merkle_tree;
pub mod neptune;
pub mod poseidon;
pub mod poseidon2;
pub mod utils;
