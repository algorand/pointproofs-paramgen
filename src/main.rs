extern crate atoi;
extern crate pairing_plus as pairing_plus;
extern crate pointproofs_paramgen;
extern crate rand;

use atoi::atoi;
use pairing_plus::serdes::SerDes;
use pointproofs_paramgen::*;
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs::File;
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
            // the initial vector is set to the first 100 digits of pi:
            // 3 .
            // 1 4 1 5 9 2 6 5 3 5 8 9 7 9 3 2 3 8 4 6
            // 2 6 4 3 3 8 3 2 7 9 5 0 2 8 8 4 1 9 7 1
            // 6 9 3 9 9 3 7 5 1 0 5 8 2 0 9 7 4 9 4 4
            // 5 9 2 3 0 7 8 1 6 4 0 6 2 8 6 2 0 8 9 9
            // 8 6 2 8 0 3 4 8 2 5 3 4 2 1 1 7 0 6 7 9
            let pi_100 = "31415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679";
            let alpha = hash_to_field_pointproofs::hash_to_field_pointproofs(pi_100);

            let params = generate(alpha, n);
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
            let params_in = PointproofsParams::deserialize(&mut f, true).unwrap();
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
                PointproofsParams::deserialize(&mut f, true).unwrap()
            };
            println!("Loading new params (with proof) from {}", &args[4]);
            let mut f = File::open(&args[4]).unwrap();
            let params_new = PointproofsParams::deserialize(&mut f, true).unwrap();
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
            let params_in = PointproofsParams::deserialize(&mut f, true).unwrap();
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
