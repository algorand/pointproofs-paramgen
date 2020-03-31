extern crate pairing_plus as pairing_plus;
use pairing_plus::bls12_381;
use pairing_plus::bls12_381::Fr;
use pairing_plus::serdes::SerDes;

extern crate ff_zeroize as ff;

use ff::PrimeField;

use std::fs::File;

extern crate rand;
use rand::rngs::OsRng;
use rand::RngCore;

extern crate veccom_paramgen;
use veccom_paramgen::*;

extern crate atoi;
use atoi::atoi;

use zeroize::Zeroize;

fn usage(progname: &str) {
    eprintln!("Usage:
	{0} init /tmp/params.out parameter_n
		Generates starting parameters with alpha = 2
	{0} evolve id_string /tmp/params.in /tmp/params.out
		Reads old params from /tmp/params.in, rerandomizes them and writes them (with a proof of knowledge of the mixed-in exponent) to /tmp/params.out, using id_string as your identity
	{0} verify id_string /tmp/params.old /tmp/params.new
		Given assumed-good old params and a newly rerandomized version (with a proof of knowledge of the mixed-in exponent), verify that the new parameters were rerandomized correctly (i.e., check that the parameters are self-consistent and that the proof is correct for the given prover identity).
	{0} finalize beacon_value /tmp/params.in /tmp/params.final
		Given assumed-good params in /tmp/params.in and the value of the shared random beacon, output the final set of parameters.
", progname);
}

fn main() {
    // let n = 1024;
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        usage(&args[0]);
        return;
    }
    match args[1].as_str() {
        "init" => {
            // parse the parameter n, a usize
            let n = match atoi::<usize>(args[3].as_bytes()) {
                Some(p) => p,
                None => {
                    usage(&args[0]);
                    return;
                }
            };

            let mut f = File::create(&args[2]).unwrap();
            println!("Generating...");
            let params = generate(Fr::from_repr(bls12_381::FrRepr::from(2)).unwrap(), n);
            println!("Generated.");
            params.serialize(&mut f, true).unwrap();
        }
        "evolve" => {
            if args.len() < 5 {
                usage(&args[0]);
                return;
            }
            let id = args[2].as_bytes();
            println!("Loading params...");
            let mut f = File::open(&args[3]).unwrap();
            let params_in = VeccomParams::deserialize(&mut f, true).unwrap();
            println!("Loaded.");
            println!("Checking...");
            if !consistent(&params_in) {
                panic!("Input params are not consistent");
            } else {
                println!("Input params OK");
            }

            println!("Randomizing...");
            let mut r: [u8; 64] = [0; 64];
            OsRng {}.fill_bytes(&mut r[..]);
            let (params_out, proof) = rerandomize(&params_in, &r[..], &id);
            r.zeroize();
            println!("Sanity-checking proof we just created...");
            println!(
                "{}",
                check_rerandomization(&params_out, params_in.g2_alpha_1_to_n[0], &proof, &id)
            );

            println!("Serializing params and proof to {}", &args[4]);
            let mut f = File::create(&args[4]).unwrap();
            params_out.serialize(&mut f, true).unwrap();
            proof.serialize(&mut f, true).unwrap();
            println!("Done!");
        }
        "verify" => {
            if args.len() < 5 {
                usage(&args[0]);
                return;
            }
            let id = args[2].as_bytes();
            println!("Loading old (assumed-good) params from {}", &args[3]);
            let params_old = {
                let mut f = File::open(&args[3]).unwrap();
                VeccomParams::deserialize(&mut f, true).unwrap()
            };
            println!("Loading new params (with proof) from {}", &args[4]);
            let mut f = File::open(&args[4]).unwrap();
            let params_new = VeccomParams::deserialize(&mut f, true).unwrap();
            let proof = schnorr::PoK::deserialize(&mut f, true).unwrap();

            println!("Verifying...");
            if check_rerandomization(&params_new, params_old.g2_alpha_1_to_n[0], &proof, &id) {
                println!("Success!");
            } else {
                println!("FAILURE: Parameters or proof incorrect");
                println!("consistent: {}", consistent(&params_new));
            }
        }
        "finalize" => {
            if args.len() < 5 {
                usage(&args[0]);
                return;
            }
            let beacon = args[2].as_bytes();
            println!("Loading params...");
            let mut f = File::open(&args[3]).unwrap();
            let params_in = VeccomParams::deserialize(&mut f, true).unwrap();
            println!("Loaded.");
            println!("Computing final parameters...");
            let (params_out, _) = rerandomize(&params_in, &beacon, b""); // Since the beacon value is public, we don't care about the schnorr proof, so we don't care about id_string here
            println!("Computed.");
            println!("Serializing final params to {}", &args[4]);
            let mut f = File::create(&args[4]).unwrap();
            params_out.serialize(&mut f, true).unwrap();
            println!("Done!");
        }
        _ => {
            usage(&args[0]);
        }
    }
}
