use pairing_plus::{CurveAffine, CurveProjective, EncodedPoint};
use pairing_plus::hash_to_field::HashToField;
use pairing_plus::bls12_381::{G1, G1Affine, G1Compressed, Fr, FrRepr};
use pairing_plus::serdes::SerDes;

extern crate ff;
use ff::{Field, PrimeField, PrimeFieldRepr};

use std::convert::TryInto;

use crate::random_scalar;

use std::io::{Error, ErrorKind, Read, Result, Write};

pub struct PoK {
	pub g1x : G1Affine, // g_1^x, where we're proving knowledge of x
	a : G1Compressed,
	s : Fr,
}

// Make a schnorr proof-of-knowledge of a scalar x.
// id is an arbitrary bytestring that gets hashed into the challenge
// For the parameter generation protocol, each party must have a distinct id
// NOT constant time!
pub fn make_pok(x : Fr, id : &[u8]) -> PoK {
	// p = g_1^x
	// p_bytes = encode(p)
	// k <- uniform scalar
	// a = g_1^k
	// a_bytes = encode(a)
	// len_id = len(id) as 8 byte big-endian
	// hash_input = "DomainSep" || a_bytes || p_bytes || len_id || id
	// e = hash_to_scalar(hash_input)
	// s = k - e * x (as Fr elements)
	// s_bytes = encode(s)
	// output a_bytes || s_bytes
	let p : G1Affine = G1Affine::one().mul(x).into_affine();
	let p_bytes : G1Compressed = p.into_compressed();
	let k : Fr = random_scalar(); // TODO: should this be deterministic?
	let a : G1Compressed = G1Affine::one().mul(k).into_affine().into_compressed();
	let a_bytes : &[u8] = a.as_ref();
	let mut hash_input : Vec<u8> = vec![];
	hash_input.extend_from_slice(b"DomainSep"); // TODO: replace with actual domain separation prefix
	hash_input.extend_from_slice(&a_bytes);
	hash_input.extend_from_slice(p_bytes.as_ref());
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
	PoK{g1x: p, a: a, s: s}
}

pub fn verify_pok(pok : &PoK, id : &[u8]) -> bool {
	// decode compressed G1 elts P and A and scalar S from PoK, reject on error
	// (assume p has already been checked to be in the subgroup)
	// (decompression ensures on curve and in subgroup)
	// a_bytes = encode(a) // re-encode
	// p_bytes = encode(p) // re-encode
	// len_id = len(id) as 8 byte big-endian
	// hash_input = "DomainSep" || a_bytes || p_bytes || len_id || id
	// e = hash_to_scalar(hash_input)
	// b = g_1^s * p^e
	// check b == a
	let a = match pok.a.into_affine() {
		Ok(pt) => pt,
		Err(_) => return false,
	};
	let p = pok.g1x;
	let s = pok.s;
	let a_bytes : G1Compressed = G1Compressed::from_affine(a);
	let p_bytes : G1Compressed = G1Compressed::from_affine(p);

	let mut hash_input : Vec<u8> = vec![];
	hash_input.extend_from_slice(b"DomainSep"); // TODO: replace with actual domain separation prefix
	hash_input.extend_from_slice(&a_bytes.as_ref());
	hash_input.extend_from_slice(&p_bytes.as_ref());
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
	let mut a = G1Compressed::empty();
	r.read_exact(a.as_mut())?;
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
        //self.a.serialize(w, true)?;
	w.write_all(self.a.as_ref())?;
	self.s.into_repr().write_be(w)?;
        Ok(())
    }
}
