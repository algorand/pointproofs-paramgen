use pairing_plus::{CurveAffine, CurveProjective, SubgroupCheck};
use pairing_plus::hash_to_field::HashToField;
use pairing_plus::bls12_381::{G1, G1Affine, Fr};
use pairing_plus::serdes::SerDes;

extern crate ff;
use ff::{Field};

extern crate zeroize;
use zeroize::Zeroize;

use std::convert::TryInto;

use crate::random_scalar;

use std::io::{Error, ErrorKind, Read, Result, Write};

pub struct PoK {
	pub g1x : G1Affine, // g_1^x, where we're proving knowledge of x
	a : G1Affine,
	s : Fr,
}

// Make a schnorr proof-of-knowledge of a scalar x.
// id is an arbitrary bytestring that gets hashed into the challenge
// For the parameter generation protocol, each party must have a distinct id
// NOT constant time!
pub fn make_pok(x : Fr, id : &[u8]) -> PoK {
	// p = g_1^x
	// k <- uniform scalar
	// a = g_1^k
	// len_id = len(id) as 8 byte big-endian
	// a_bytes = encode(a)
	// p_bytes = encode(p)
	// hash_input = "DomainSep" || a_bytes || p_bytes || len_id || id
	// e = hash_to_scalar(hash_input)
	// s = k - e * x (as Fr elements)
	// output p, a, s
	let p : G1Affine = G1Affine::one().mul(x).into_affine();
	let mut k : Fr = random_scalar(); // mutable so we can zeroize later
	let a : G1Affine = G1Affine::one().mul(k).into_affine();
	let mut hash_input : Vec<u8> = vec![];
	hash_input.extend_from_slice(b"DomainSep"); // TODO: replace with actual domain separation prefix
	a.serialize(&mut hash_input, true).unwrap();
	p.serialize(&mut hash_input, true).unwrap();
	let len_id : u64 = id.len().try_into().unwrap();
	hash_input.extend_from_slice(&len_id.to_be_bytes());
	hash_input.extend_from_slice(id);
	let e : Fr = HashToField::new(&hash_input, None).with_ctr(0);
	let s : Fr = {
		let mut s : Fr = e;
		s.mul_assign(&x);
		s.negate();
		s.add_assign(&k);
		s
	};
	k.zeroize();
	PoK{g1x: p, a: a, s: s}
}

// Verify a Schnorr proof-of-knowledge.
// For safety, this function checks that the points are valid group elements.
pub fn verify_pok(pok : &PoK, id : &[u8]) -> bool {
	// check p and a are in supgroup
	// a_bytes = encode(a)
	// p_bytes = encode(p)
	// len_id = len(id) as 8 byte big-endian
	// hash_input = "DomainSep" || a_bytes || p_bytes || len_id || id
	// e = hash_to_scalar(hash_input)
	// b = g_1^s * p^e
	// check b == a
	let a = pok.a;
	let p = pok.g1x;
	if !(a.in_subgroup() && p.in_subgroup()) {
		return false;
	}
	let s = pok.s;

	let mut hash_input : Vec<u8> = vec![];
	hash_input.extend_from_slice(b"DomainSep"); // TODO: replace with actual domain separation prefix
	a.serialize(&mut hash_input, true).unwrap();
	p.serialize(&mut hash_input, true).unwrap();
	let len_id : u64 = id.len().try_into().unwrap();
	hash_input.extend_from_slice(&len_id.to_be_bytes());
	hash_input.extend_from_slice(id);
	let e : Fr = HashToField::new(&hash_input, None).with_ctr(0);

	let b : G1Affine = {
		let mut b : G1 = p.mul(e);
		let g1s = G1Affine::one().mul(s);
		b.add_assign(&g1s);
		b.into_affine()
	};
	b == a
}

impl SerDes for PoK {
    fn deserialize<R: Read>(r: &mut R, compressed: bool) -> Result<Self> {
        if !compressed {
            return Err(Error::new(
                ErrorKind::Other,
                "PoK can only be (de)serialized with compressed=true",
            ));
        }
	let g1x = G1Affine::deserialize(r, true)?;
	let a = G1Affine::deserialize(r, true)?;
	let s : Fr = Fr::deserialize(r, true)?;
        Ok(PoK{g1x, a, s})
    }
    fn serialize<W: Write>(&self, w: &mut W, compressed: bool) -> Result<()> {
        if !compressed {
            return Err(Error::new(
                ErrorKind::Other,
                "PoK can only be (de)serialized with compressed=true",
            ));
        }
        self.g1x.serialize(w, true)?;
        self.a.serialize(w, true)?;
	self.s.serialize(w, true)?;
        Ok(())
    }
}
