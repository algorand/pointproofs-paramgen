use ff::PrimeField;
use pairing_plus::bls12_381::*;
use pairing_plus::serdes::SerDes;
#[test]
fn test_read_param() {
    let mut f = std::fs::File::open("first.param").unwrap();

    let _t = crate::VeccomParams::deserialize(&mut f, true).unwrap();
}

#[test]
fn test_param2() {
    println!("begin");
    let alpha = Fr::from_repr(FrRepr([5, 0, 0, 0])).unwrap();
    println!("alpha {:?}", alpha);
    let t = crate::generate(alpha);
    println!("param generated");
    let mut f = std::fs::File::create("3.param").unwrap();
    t.serialize(&mut f, true).unwrap();
    println!("finished serilization");

    let mut ff = std::fs::File::open("3.param").unwrap();

    let _tt = crate::VeccomParams::deserialize(&mut ff, true).unwrap();
}
