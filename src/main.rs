extern crate pairing_plus as pairing_plus;
use pairing_plus::bls12_381;
use pairing_plus::bls12_381::Fr;
use pairing_plus::serdes::SerDes;

extern crate ff;

use ff::PrimeField;

use std::fs::File;

extern crate rand;
use rand::rngs::OsRng;
use rand::RngCore;

extern crate veccom_paramgen;
use veccom_paramgen::*;

fn usage(progname: &str) {
    eprintln!("Usage:
	{0} generate /tmp/params.out
		Generates starting parameters with alpha = 2
	{0} evolve /tmp/params.in /tmp/params.out
		Reads old params from /tmp/params.in, rerandomizes them and writes them (with a proof of knowledge of the mixed-in exponent) to /tmp/params.out
	{0} verify /tmp/params.old /tmp/params.new
		Given assumed-good old params and a newly rerandomized version (with a proof of knowledge of the mixed-in exponent), verify that the new parameters were rerandomized correctly (i.e., check that the parameters are self-consistent and that the proof is correct).
", progname);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        usage(&args[0]);
        return;
    }
    match args[1].as_str() {
        "generate" => {
            let mut f = File::create(&args[2]).unwrap();
            println!("Generating...");
            let params = generate(Fr::from_repr(bls12_381::FrRepr::from(2)).unwrap());
            println!("Generated.");
            params.serialize(&mut f, true).unwrap();
        }
        "evolve" => {
            if args.len() < 4 {
                usage(&args[0]);
                return;
            }
            println!("Loading params...");
            let mut f = File::open(&args[2]).unwrap();
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
            let (params_out, proof) = rerandomize(&params_in, &r[..]);
            println!("Sanity-checking proof we just created...");
            println!(
                "{}",
                check_rerandomization(&params_out, params_in.g1_alpha_1_to_n[0], &proof)
            );

            println!("Serializing params and proof to {}", &args[3]);
            let mut f = File::create(&args[3]).unwrap();
            params_out.serialize(&mut f, true).unwrap();
            proof.serialize(&mut f, true).unwrap();
            println!("Done!");
        }
        "verify" => {
            if args.len() < 4 {
                usage(&args[0]);
                return;
            }
            println!("Loading old (assumed-good) params from {}", &args[2]);
            let params_old = {
                let mut f = File::open(&args[2]).unwrap();
                VeccomParams::deserialize(&mut f, true).unwrap()
            };
            println!("Loading new params (with proof) from {}", &args[3]);
            let mut f = File::open(&args[3]).unwrap();
            let params_new = VeccomParams::deserialize(&mut f, true).unwrap();
            let proof = PoK::deserialize(&mut f, true).unwrap();

            println!("Verifying...");
            if check_rerandomization(&params_new, params_old.g1_alpha_1_to_n[0], &proof) {
                println!("Success!");
            } else {
                println!("FAILURE: Parameters or proof incorrect");
                println!("consistent: {}", consistent(&params_new));
            }
        }
        _ => {
            usage(&args[0]);
        }
    }
}
