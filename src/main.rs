extern crate pairing_plus as pairing;
use pairing::{CurveAffine, CurveProjective};
use pairing::bls12_381;
use pairing::bls12_381::{Bls12, G1Affine, G2Affine, G1, G2, G2Compressed, Fr, FrRepr, Fq12};
use pairing::{EncodedPoint, Engine};
use pairing::hash_to_curve::HashToCurve;
use pairing::serdes::SerDes;
use pairing::hash_to_field::FromRO;

use std::io::{Read, Write, Result};

extern crate ff;
use ff::Field;
use ff::PrimeField;

use std::fs::File;

extern crate rand;
use rand::rngs::OsRng;
use rand::RngCore;

const N : usize = 1024;

pub struct VeccomParams {
	/// g1^{alpha}, g1^{alpha^2}, ..., g1^{alpha^N}
	g1_alpha_1_to_n : [G1Affine; N],

	/// g1^{alpha^{N+2}}, g1^{alpha^{N+3}}, ..., g1^{alpha^{2N}}
	g1_alpha_nplus2_to_2n : [G1Affine; N - 1],

	/// g2^{alpha}, ..., g2^{alpha^N}
	g2_alpha_1_to_n : [G2Affine; N],

	/// e(g1,g2)^{alpha^{N+1}}
	gt_alpha_nplus1 : Fq12
}

impl VeccomParams {
	pub fn serialize<W: Write> (&self, w : &mut W) -> Result<()> {
		for pt in &self.g1_alpha_1_to_n[..] {
			pt.serialize(w, true)?;
		}
		for pt in &self.g1_alpha_nplus2_to_2n[..] {
			pt.serialize(w, true)?;
		}
		for pt in &self.g2_alpha_1_to_n[..] {
			pt.serialize(w, true)?;
		}
		self.gt_alpha_nplus1.serialize(w, true)?;
		Ok(())
	}
	pub fn deserialize<R: Read> (r : &mut R) -> Result<Self> {
		let mut g1_alpha_1_to_n = [G1Affine::zero(); N];
		let mut g1_alpha_nplus2_to_2n = [G1Affine::zero(); N-1];
		let mut g2_alpha_1_to_n = [G2Affine::zero(); N];
		let gt_alpha_nplus1 : Fq12;
		for elt in g1_alpha_1_to_n[..].iter_mut() {
			*elt = G1Affine::deserialize(r, true)?;
		}
		for elt in g1_alpha_nplus2_to_2n[..].iter_mut() {
			*elt = G1Affine::deserialize(r, true)?;
		}
		for elt in g2_alpha_1_to_n[..].iter_mut() {
			*elt = G2Affine::deserialize(r, true)?;
		}
		gt_alpha_nplus1 = Fq12::deserialize(r, true)?;
		let params = VeccomParams{
			g1_alpha_1_to_n: g1_alpha_1_to_n, 
			g1_alpha_nplus2_to_2n: g1_alpha_nplus2_to_2n,
			g2_alpha_1_to_n: g2_alpha_1_to_n, 
			gt_alpha_nplus1: gt_alpha_nplus1
		};
		Ok(params)
	}
}

// Proof of knowledge of exponent
pub struct PoK {
	g2beta : G2Affine, // g2^beta (where we're proving knowledge of beta)
	hg1beta : G1Affine // HashToG1(g2beta)^beta
}

fn random_scalar() -> Fr {
	let mut r : [u8; 64] = [0; 64];
	OsRng{}.fill_bytes(&mut r[..]);
	// For convenience, just using already-implemented hash-to-field
	Fr::from_ro(r.as_ref(),0)
}

// Checks that a set of parameters are in the correct form (g1^alpha, g1^alpha^2, etc.) for some alpha
fn consistent(params : &VeccomParams) -> bool {
	// First, check all points are in the group, nonzero, and not the generator
	// (Subgroup check is already done in our deserialization code)
	if params.g1_alpha_1_to_n.iter().any(|&x| x == G1Affine::zero() || x == G1Affine::one()) {
		println!("g1_alpha_1_to_n points must be nonzero and not the generator");
		return false;
	}

	if params.g1_alpha_nplus2_to_2n.iter().any(|&x| x == G1Affine::zero() || x == G1Affine::one()) {
		println!("g1_alpha_nplus2_to_2n points must be nonzero and not the generator");
		return false;
	}

	if params.g2_alpha_1_to_n.iter().any(|&x| x == G2Affine::zero() || x == G2Affine::one()) {
		println!("g2_alpha_1_to_n points must be nonzero and not the generator");
		return false;
	}

	// Generate N random scalars r_1, ..., r_N
	let mut rs_owned : Vec<FrRepr> = vec![];
	let mut rs : Vec<&[u64;4]> = vec![];
	for _ in 0..N {
		let r = random_scalar().into_repr();
		rs_owned.push(r);
	}
	for i in 0..N {
		rs.push(&rs_owned[i].0);
	}

	// Compute:
	// S = prod_{i=1}^{N-1} ("g_1^{alpha^i}")^{r_i}
	// R_1 = prod_{i=1}^{N} ("g_1^{alpha^i}")^{r_i} = S * ("g_1^{alpha^N}")^{r_N}
	// R_2 = prod_{i=1}^{N} ("g_2^{alpha^i}")^{r_i}
	// T = prod{i=1}^{N-1} ("g_1^{alpha^{i+1}}")^{r_i}
	// U = prod{i=1}^{N-1} ("g_1^{alpha^{i+N+1}")^{r_i}
	let pt_s : bls12_381::G1Affine = G1Affine::sum_of_products(&params.g1_alpha_1_to_n[0..=N-2] , &rs[0..=N-2]).into_affine();
	let pt_r1 : bls12_381::G1Affine = {
		let mut tmp = params.g1_alpha_1_to_n[N-1].mul(Fr::from_repr(rs_owned[N-1]).unwrap());
		tmp.add_assign_mixed(&pt_s);
		tmp.into_affine()
	};
	let pt_r2 = G2Affine::sum_of_products(&params.g2_alpha_1_to_n[0..=N-1] , &rs[0..=N-1]).into_affine();
	let pt_t = G1Affine::sum_of_products(&params.g1_alpha_1_to_n[1..=N-1], &rs[0..=N-2]).into_affine();
	let pt_u = G1Affine::sum_of_products(&params.g1_alpha_nplus2_to_2n[0..=N-2], &rs[0..=N-2]).into_affine();


	let g1 = G1Affine::one();
	let g2 = G2Affine::one();
	let g2alpha = &params.g2_alpha_1_to_n[0];

	// Then check
	// 1: e(R_1, g_2) = e(g_1, R_2)
	// which essentially checks e("g_1^{alpha^i}", g_2) = e(g_1, "g_2^{alpha^i}") for all 1<=i<=N
	if g2.pairing_with(&pt_r1) != g1.pairing_with(&pt_r2) {
		return false;
	}

	// 2: e(S, g_2^alpha) = e(T, g_2)
	// which essentially checks e("g_1^{alpha^i}", g_2^alpha) = e(g_1^{alpha^{i+1}}) for all 1<=i<=N-1
	if pt_s.pairing_with(g2alpha) != pt_t.pairing_with(&g2) {
		return false;
	}

	// 3: e(g_1^{alpha^N}, g_2^alpha) = "e(g_1, g_2)^{alpha^{N+1}}"
	let mut tmp = params.g1_alpha_1_to_n[N-1].pairing_with(g2alpha);
	tmp.sub_assign(&params.gt_alpha_nplus1);
	if !tmp.is_zero() {
		return false;
	}

	// 4: e(T, g_2^{alpha^N}) = e(U, g_2)
	if pt_t.pairing_with(&params.g2_alpha_1_to_n[N-1]) != pt_u.pairing_with(&g2) {
		return false;
	}

	true
}

fn makepok(beta : Fr) -> PoK {
	let g2beta = G2Affine::one().mul(beta).into_affine();
	// pok is supposed to be HashToG1("VecCom param gen proof of possession", g2beta.serialize())^beta
	let mut h = G1::hash_to_curve(G2Compressed::from_affine(g2beta), "VecCom param gen proof of possession");
	h.mul_assign(beta);
	PoK{g2beta: g2beta, hg1beta: h.into_affine()}
}

fn checkpok(pok : &PoK) -> bool {
	// h2g1 is supposed to be HashToG1("VecCom param gen proof of possession", g2beta.serialize())^beta
	if pok.hg1beta.is_zero() || pok.g2beta.is_zero() {
		return false;
	}
	let h = {
		let mut h = G1::hash_to_curve(G2Compressed::from_affine(pok.g2beta), "VecCom param gen proof of possession");
		h.negate();
		h
	};
	Bls12::pairing_product(pok.hg1beta,G2Affine::one(),h.into_affine(),pok.g2beta) == Fq12::one()
}

fn check_rerandomization(params : &VeccomParams, g1alpha_old : G1Affine, proof : PoK) -> bool {
	let g2inv = {
		let mut g = G2Affine::one();
		g.negate();
		g
	};

	checkpok(&proof) &&
	(Bls12::pairing_product(g1alpha_old, proof.g2beta, params.g1_alpha_1_to_n[0], g2inv) == Fq12::one()) &&
	consistent(params)
}

pub fn generate(alpha : Fr) -> VeccomParams {
	let mut g1_alpha_1_to_n : [G1Affine; N] = [G1Affine::zero(); N];
	let mut g1_alpha_nplus2_to_2n : [G1Affine; N - 1] = [G1Affine::zero(); N-1];
	let mut g2_alpha_1_to_n : [G2Affine; N] = [G2Affine::zero(); N];
	
	let mut scalar : Fr = alpha;
	for i in 1..=N {
		// scalar = alpha^i

		let mut pt1 = G1::one();
		pt1.mul_assign(scalar);
		g1_alpha_1_to_n[i-1] = pt1.into_affine();
		let mut pt2 = G2::one();
		pt2.mul_assign(scalar);
		g2_alpha_1_to_n[i-1] = pt2.into_affine();

		scalar.mul_assign(&alpha);
		// scalar = alpha^{i+1}
	}
	// scalar = alpha^{N+1}

	let gt_alpha_nplus1 = G1Affine::one().mul(scalar).into_affine().pairing_with(&G2Affine::one());
	scalar.mul_assign(&alpha);

	// scalar = alpha^{N+2}
	for i in 1..=N-1 {
		let mut pt1 = G1::one();
		pt1.mul_assign(scalar);
		g1_alpha_nplus2_to_2n[i-1] = pt1.into_affine();
		scalar.mul_assign(&alpha);
	}

	VeccomParams{
		g1_alpha_1_to_n,
		g1_alpha_nplus2_to_2n,
		g2_alpha_1_to_n,
		gt_alpha_nplus1
	}
}

fn rerandomize(params : &VeccomParams, alpha : Fr) -> (VeccomParams, PoK) {
	let mut g1_alpha_1_to_n : [G1Affine; N] = [G1Affine::zero(); N];
	let mut g1_alpha_nplus2_to_2n : [G1Affine; N - 1] = [G1Affine::zero(); N-1];
	let mut g2_alpha_1_to_n : [G2Affine; N] = [G2Affine::zero(); N];
	
	let mut scalar : Fr = alpha;
	for i in 1..=N {
		// scalar = alpha^i
		g1_alpha_1_to_n[i-1] = params.g1_alpha_1_to_n[i-1].mul(scalar).into_affine();
		g2_alpha_1_to_n[i-1] = params.g2_alpha_1_to_n[i-1].mul(scalar).into_affine();
		scalar.mul_assign(&alpha);
		// scalar = alpha^{i+1}
	}
	// scalar = alpha^{N+1}
	let gt_alpha_nplus1 = g1_alpha_1_to_n[N-1].pairing_with(&g2_alpha_1_to_n[0]);
	scalar.mul_assign(&alpha);

	// scalar = alpha^{N+2}
	for i in 1..=N-1 {
		g1_alpha_nplus2_to_2n[i-1] = params.g1_alpha_nplus2_to_2n[i-1].mul(scalar).into_affine();
		scalar.mul_assign(&alpha);
	}
	(VeccomParams{
		g1_alpha_1_to_n,
		g1_alpha_nplus2_to_2n,
		g2_alpha_1_to_n,
		gt_alpha_nplus1
	}, makepok(alpha))
}

fn main() {
	/*
	println!("Generating...");
	let params = generate(Fr::from_repr(bls12_381::FrRepr::from(2)).unwrap());
	println!("Generated.");
	let mut f = File::create("/tmp/params.2").unwrap();
	&params.serialize(&mut f).unwrap();
	*/

	println!("Loading params from /tmp/params.in...");
	let mut f = File::open("/tmp/params.in").unwrap();
	let params = VeccomParams::deserialize(&mut f).unwrap();
	println!("Loaded.");
	println!("Checking...");
	if !consistent(&params) {
		panic!("Input params are not consistent");
	} else {
		println!("OK");
	}

	println!("Randomizing...");
	let r = random_scalar();
	let (params2, proof) = rerandomize(&params, r);
	println!("Checking proof we just created...");
	println!("{}", check_rerandomization(&params2, params.g1_alpha_1_to_n[0], proof));

	println!("Serializing params to /tmp/params.out");
	let mut f = File::create("/tmp/params.out").unwrap();
	&params2.serialize(&mut f).unwrap();
	println!("Done!");
}
