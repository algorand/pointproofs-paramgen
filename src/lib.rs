extern crate pairing_plus as pairing_plus;
use pairing_plus::bls12_381;
use pairing_plus::bls12_381::{Bls12, Fq12, Fr, FrRepr, G1Affine, G2Affine, G1, G2};
use pairing_plus::hash_to_field::FromRO;
use pairing_plus::serdes::SerDes;
use pairing_plus::Engine;
use pairing_plus::{CurveAffine, CurveProjective};

use std::io::{Error, ErrorKind, Read, Result, Write};

extern crate ff;
use ff::Field;
use ff::PrimeField;

extern crate rand;
use rand::rngs::OsRng;
use rand::RngCore;

extern crate bls_sigs_ref as bls;
use bls::BLSSigCore;
use bls::BLSSignaturePop;

#[cfg(test)]
mod test;

//const N: usize = 1024;

#[derive(Debug, PartialEq)]
pub struct VeccomParams {
    /// ciphersuite id
    pub ciphersuite: u8,

    /// parameter N
    pub n: usize,

    /// g1^{alpha}, g1^{alpha^2}, ..., g1^{alpha^N}
    pub g1_alpha_1_to_n: Vec<G1Affine>, // [G1Affine; N],

    /// g1^{alpha^{N+2}}, g1^{alpha^{N+3}}, ..., g1^{alpha^{2N}}
    pub g1_alpha_nplus2_to_2n: Vec<G1Affine>, // [G1Affine; N - 1],

    /// g2^{alpha}, ..., g2^{alpha^N}
    pub g2_alpha_1_to_n: Vec<G2Affine>, //[G2Affine; N],

    /// e(g1,g2)^{alpha^{N+1}}
    pub gt_alpha_nplus1: Fq12,
}

impl SerDes for VeccomParams {
    fn serialize<W: Write>(&self, w: &mut W, compressed: bool) -> Result<()> {
        if !compressed {
            return Err(Error::new(
                ErrorKind::Other,
                "veccom params can only be (de)serialized with compressed=true",
            ));
        }
        w.write_all(&[self.ciphersuite])?;
        w.write_all(&self.n.to_le_bytes())?;
        for pt in &self.g1_alpha_1_to_n {
            pt.serialize(w, true)?;
        }
        for pt in &self.g1_alpha_nplus2_to_2n {
            pt.serialize(w, true)?;
        }
        for pt in &self.g2_alpha_1_to_n {
            pt.serialize(w, true)?;
        }
        self.gt_alpha_nplus1.serialize(w, true)?;
        Ok(())
    }
    fn deserialize<R: Read>(r: &mut R, compressed: bool) -> Result<Self> {
        if !compressed {
            return Err(Error::new(
                ErrorKind::Other,
                "veccom params can only be (de)serialized with compressed=true",
            ));
        }

        // read ciphersuite
        let mut ciphersuite = [0u8; 1];
        r.read_exact(&mut ciphersuite)?;

        // read parameter n
        let mut buf = [0u8; 8];
        r.read_exact(&mut buf)?;
        let n = usize::from_le_bytes(buf);

        if n > 65535 {
            return Err(Error::new(
                ErrorKind::Other,
                "The size of n has passed the maximal allowed value.",
            ));
        }

        let mut g1_alpha_1_to_n: Vec<G1Affine> = vec![];
        let mut g1_alpha_nplus2_to_2n: Vec<G1Affine> = vec![];
        let mut g2_alpha_1_to_n: Vec<G2Affine> = vec![];
        let gt_alpha_nplus1: Fq12;

        for _ in 0..n {
            let tmp = G1Affine::deserialize(r, true)?;
            g1_alpha_1_to_n.push(tmp);
        }
        for _ in 0..n - 1 {
            let tmp = G1Affine::deserialize(r, true)?;
            g1_alpha_nplus2_to_2n.push(tmp);
        }
        for _ in 0..n {
            let tmp = G2Affine::deserialize(r, true)?;
            g2_alpha_1_to_n.push(tmp);
        }

        gt_alpha_nplus1 = Fq12::deserialize(r, true)?;

        Ok(VeccomParams {
            ciphersuite: ciphersuite[0],
            n,
            g1_alpha_1_to_n,
            g1_alpha_nplus2_to_2n,
            g2_alpha_1_to_n,
            gt_alpha_nplus1,
        })
    }
}

// Proof of knowledge of exponent
pub struct PoK {
    g2beta: G2Affine, // g2^beta (where we're proving knowledge of beta)
    pop: G1Affine,    // HashToG1(g2beta)^beta
}

impl SerDes for PoK {
    fn deserialize<R: Read>(r: &mut R, compressed: bool) -> Result<Self> {
        if !compressed {
            return Err(Error::new(
                ErrorKind::Other,
                "PoK can only be (de)serialized with compressed=true",
            ));
        }
        let g2beta = G2Affine::deserialize(r, true)?;
        let pop = G1Affine::deserialize(r, true)?;
        Ok(PoK { g2beta, pop })
    }
    fn serialize<W: Write>(&self, w: &mut W, compressed: bool) -> Result<()> {
        if !compressed {
            return Err(Error::new(
                ErrorKind::Other,
                "PoK can only be (de)serialized with compressed=true",
            ));
        }
        self.g2beta.serialize(w, true)?;
        self.pop.serialize(w, true)?;
        Ok(())
    }
}

fn random_scalar() -> Fr {
    let mut r: [u8; 64] = [0; 64];
    OsRng {}.fill_bytes(&mut r[..]);
    // For convenience, just using already-implemented hash-to-field
    Fr::from_ro(r.as_ref(), 0)
}

// Checks that a set of parameters are in the correct form (g1^alpha, g1^alpha^2, etc.) for some alpha
pub fn consistent(params: &VeccomParams) -> bool {
    // First, check all points are in the group, nonzero, and not the generator
    // (Subgroup check is already done in our deserialization code)
    if params
        .g1_alpha_1_to_n
        .iter()
        .any(|&x| x == G1Affine::zero() || x == G1Affine::one())
    {
        return false;
    }

    if params
        .g1_alpha_nplus2_to_2n
        .iter()
        .any(|&x| x == G1Affine::zero() || x == G1Affine::one())
    {
        return false;
    }

    if params
        .g2_alpha_1_to_n
        .iter()
        .any(|&x| x == G2Affine::zero() || x == G2Affine::one())
    {
        return false;
    }

    // Generate N random scalars r_1, ..., r_N
    let mut rs_owned: Vec<FrRepr> = vec![];
    let mut rs: Vec<&[u64; 4]> = vec![];
    for _ in 0..params.n {
        let r = random_scalar().into_repr();
        rs_owned.push(r);
    }
    for item in rs_owned.iter() {
        rs.push(&item.0);
    }

    // Compute:
    // S = prod_{i=1}^{N-1} ("g_1^{alpha^i}")^{r_i}
    // R_1 = prod_{i=1}^{N} ("g_1^{alpha^i}")^{r_i} = S * ("g_1^{alpha^N}")^{r_N}
    // R_2 = prod_{i=1}^{N} ("g_2^{alpha^i}")^{r_i}
    // T = prod{i=1}^{N-1} ("g_1^{alpha^{i+1}}")^{r_i}
    // U = prod{i=1}^{N-1} ("g_1^{alpha^{i+N+1}")^{r_i}
    let pt_s: bls12_381::G1Affine = G1Affine::sum_of_products(
        &params.g1_alpha_1_to_n[0..params.n - 1],
        &rs[0..params.n - 1],
    )
    .into_affine();
    let pt_r1: bls12_381::G1Affine = {
        let mut tmp = params.g1_alpha_1_to_n[params.n - 1]
            .mul(Fr::from_repr(rs_owned[params.n - 1]).unwrap());
        tmp.add_assign_mixed(&pt_s);
        tmp.into_affine()
    };
    let pt_r2 = G2Affine::sum_of_products(&params.g2_alpha_1_to_n[0..params.n], &rs[0..params.n])
        .into_affine();
    let pt_t =
        G1Affine::sum_of_products(&params.g1_alpha_1_to_n[1..params.n], &rs[0..params.n - 1])
            .into_affine();
    let pt_u = G1Affine::sum_of_products(
        &params.g1_alpha_nplus2_to_2n[0..params.n - 1],
        &rs[0..params.n - 1],
    )
    .into_affine();

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
    let mut tmp = params.g1_alpha_1_to_n[params.n - 1].pairing_with(g2alpha);
    tmp.sub_assign(&params.gt_alpha_nplus1);
    if !tmp.is_zero() {
        return false;
    }

    // 4: e(T, g_2^{alpha^N}) = e(U, g_2)
    if pt_t.pairing_with(&params.g2_alpha_1_to_n[params.n - 1]) != pt_u.pairing_with(&g2) {
        return false;
    }

    true
}

pub fn makepok<B: AsRef<[u8]>>(sk: B) -> PoK {
    let (_beta, g2beta) = <G1 as BLSSigCore>::keygen(&sk);
    let h = G1::pop_prove(sk);
    PoK {
        g2beta: g2beta.into_affine(),
        pop: h.into_affine(),
    }
}

pub fn checkpok(pok: &PoK) -> bool {
    if pok.pop.is_zero() || pok.g2beta.is_zero() {
        return false;
    }
    <G1 as BLSSignaturePop>::pop_verify(pok.g2beta.into_projective(), pok.pop.into_projective())
}

pub fn check_rerandomization(params: &VeccomParams, g1alpha_old: G1Affine, proof: &PoK) -> bool {
    let g2inv = {
        let mut g = G2Affine::one();
        g.negate();
        g
    };

    checkpok(&proof)
        && (Bls12::pairing_product(g1alpha_old, proof.g2beta, params.g1_alpha_1_to_n[0], g2inv)
            == Fq12::one())
        && consistent(params)
}

pub fn generate(alpha: Fr, ciphersuite: u8, n: usize) -> VeccomParams {
    let mut g1_alpha_1_to_n: Vec<G1Affine> = vec![]; //[G1Affine; N] = [G1Affine::zero(); N];
    let mut g1_alpha_nplus2_to_2n: Vec<G1Affine> = vec![]; //[G1Affine; N - 1] = [G1Affine::zero(); N - 1];
    let mut g2_alpha_1_to_n: Vec<G2Affine> = vec![]; // [G2Affine; N] = [G2Affine::zero(); N];

    let mut scalar: Fr = alpha;
    for _ in 1..=n {
        // scalar = alpha^i

        let mut pt1 = G1::one();
        pt1.mul_assign(scalar);
        g1_alpha_1_to_n.push(pt1.into_affine());
        //        g1_alpha_1_to_n[i - 1] = pt1.into_affine();
        let mut pt2 = G2::one();
        pt2.mul_assign(scalar);
        g2_alpha_1_to_n.push(pt2.into_affine());
        //        g2_alpha_1_to_n[i - 1] = pt2.into_affine();

        scalar.mul_assign(&alpha);
        // scalar = alpha^{i+1}
    }
    // scalar = alpha^{N+1}

    let gt_alpha_nplus1 = G1Affine::one()
        .mul(scalar)
        .into_affine()
        .pairing_with(&G2Affine::one());
    scalar.mul_assign(&alpha);

    // scalar = alpha^{N+2}
    for _ in 1..n {
        let mut pt1 = G1::one();
        pt1.mul_assign(scalar);
        g1_alpha_nplus2_to_2n.push(pt1.into_affine());
        //        g1_alpha_nplus2_to_2n[i - 1] = pt1.into_affine();
        scalar.mul_assign(&alpha);
    }

    VeccomParams {
        ciphersuite,
        n,
        g1_alpha_1_to_n,
        g1_alpha_nplus2_to_2n,
        g2_alpha_1_to_n,
        gt_alpha_nplus1,
    }
}

pub fn rerandomize<B: AsRef<[u8]>>(params: &VeccomParams, entropy: B) -> (VeccomParams, PoK) {
    let (alpha, _) = G1::keygen(&entropy);
    let n = params.n;
    let mut g1_alpha_1_to_n: Vec<G1Affine> = vec![]; //[G1Affine; N] = [G1Affine::zero(); N];
    let mut g1_alpha_nplus2_to_2n: Vec<G1Affine> = vec![]; //[G1Affine; N - 1] = [G1Affine::zero(); N - 1];
    let mut g2_alpha_1_to_n: Vec<G2Affine> = vec![]; //[G2Affine; N] = [G2Affine::zero(); N];

    let mut scalar: Fr = alpha;

    for i in 1..=n {
        // scalar = alpha^i
        g1_alpha_1_to_n.push(params.g1_alpha_1_to_n[i - 1].mul(scalar).into_affine());
        g2_alpha_1_to_n.push(params.g2_alpha_1_to_n[i - 1].mul(scalar).into_affine());
        scalar.mul_assign(&alpha);
        // scalar = alpha^{i+1}
    }
    // scalar = alpha^{N+1}
    let gt_alpha_nplus1 = g1_alpha_1_to_n[n - 1].pairing_with(&g2_alpha_1_to_n[0]);
    scalar.mul_assign(&alpha);

    // scalar = alpha^{N+2}
    for i in 1..n {
        g1_alpha_nplus2_to_2n.push(
            params.g1_alpha_nplus2_to_2n[i - 1]
                .mul(scalar)
                .into_affine(),
        );
        scalar.mul_assign(&alpha);
    }

    (
        VeccomParams {
            ciphersuite: params.ciphersuite,
            n,
            g1_alpha_1_to_n,
            g1_alpha_nplus2_to_2n,
            g2_alpha_1_to_n,
            gt_alpha_nplus1,
        },
        makepok(entropy),
    )
}
