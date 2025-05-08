/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/

use std::error::Error;
use std::fmt;

pub mod low_degree_exponent_interpolation;
pub mod sigma_correct_homomorphic_elgamal_enc;
pub mod sigma_correct_homomorphic_elgamal_encryption_of_dlog;
pub mod sigma_dlog;
pub mod sigma_ec_ddh;
pub mod sigma_valid_pedersen;
pub mod sigma_valid_pedersen_blind;
pub mod quadratic_residue_dlog;
pub mod quadratic_residue;
// pub mod range_proof;
// pub mod affine_operation;
// pub mod paillier_blum_modulus;
// pub mod affine_prime_operation;
// pub mod raw_ciphertext;

#[derive(Debug, Clone, Copy)]
pub struct ProofError;

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ProofError")
    }
}

impl Error for ProofError {
    fn description(&self) -> &str {
        "Error while verifying"
    }
}
