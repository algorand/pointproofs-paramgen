use ff::PrimeField;
use pairing_plus::bls12_381::*;
use pairing_plus::serdes::SerDes;
use rand::rngs::OsRng;
use rand::RngCore;
// #[test]
// fn test_read_param() {
//     let mut f = std::fs::File::open("first.param").unwrap();
//
//     let _t = crate::VeccomParams::deserialize(&mut f, true).unwrap();
// }

#[test]
fn test_param() {
    let alpha = Fr::from_repr(FrRepr([5, 0, 0, 0])).unwrap();
    let t = crate::generate(alpha, 0, 1024);

    let mut f = std::fs::File::create("3.param").unwrap();
    t.serialize(&mut f, true).unwrap();

    let mut ff = std::fs::File::open("3.param").unwrap();
    let tt = crate::VeccomParams::deserialize(&mut ff, true).unwrap();

    assert_eq!(t, tt);
}

#[test]
fn test_functions() {
    // generate an initial parameter set
    let alpha = Fr::from_repr(FrRepr([5, 0, 0, 0])).unwrap();
    let init_param = crate::generate(alpha, 0, 1024);

    // re-randomize the initial parameter set
    let mut r: [u8; 64] = [0; 64];
    OsRng {}.fill_bytes(&mut r[..]);

    let (update_param, proof) = crate::rerandomize(&init_param, &r[..]);
    println!("finish rerandomize");
    // check the proof
    assert!(
        crate::check_rerandomization(&update_param, init_param.g1_alpha_1_to_n[0], &proof),
        "re-randomization failed"
    );
}
