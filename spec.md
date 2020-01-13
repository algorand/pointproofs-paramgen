# vector commitment parameter generation

### types

The groups are switched to enable faster batch verification.

``` rust
/// A wrapper of BLS::G2. Groups are switched and proof/commits are in BLS::G2
type VeccomG1 = G2;
/// A wrapper of BLS::G1. Groups are switched and proof/commits are in BLS::G2
type VeccomG2 = G1;
/// A wrapper of BLS::G2Affine. Groups are switched and proof/commits are in BLS::G2
type VeccomG1Affine = G2Affine;
/// A wrapper of BLS::G1Affine. Groups are switched and proof/commits are in BLS::G2
type VeccomG2Affine = G1Affine;
}
```

## Structures


``` rust
/// Structure for porver parameters.
struct ProverParams {
    ciphersuite: u8,
    /// dimension
    n: usize,
    /// g2^{alpha}, g2^{alpha^2}, ..., g2^{alpha^2n}
    generators: Vec<VeccomG1Affine>,
}
```

``` rust
/// Structure for verifier parameters.
struct VerifierParams {
    ciphersuite: u8,
    /// dimension
    n: usize,
    /// g2^{alpha}, ..., g1^{alpha^n}
    generators: Vec<VeccomG2Affine>,
    /// e(g1,g2)^{alpha^{N+1}}
    gt_elt: Fq12,
}
```

``` rust
// Proof of knowledge of exponent
// Change this to schnor signature?
pub struct PoK {
    g1beta: G1Affine, // g1^beta (where we're proving knowledge of beta)
    pop: G2Affine,    // HashToG2(g1beta)^beta
}
```

## Serialization

Serialization is implemented for `ProverParams`, `VerifierParams` and `PoK`
``` rust
fn serialize<W: Write>(&self, w: &mut W, compressed: bool) -> Result<()>;
fn deserialize<R: Read>(r: &mut R, compressed: bool) -> Result<Self>;
```

## APIs

``` rust
// Input a seed,
// generate a string which is the encoding of a new set of parameters,
// as well as a prove of knowledge.
fn param_new<Blob: AsRef<[u8]>>(seed: Blob) -> (Blob, Blob);
```

Steps:
* `r = hash_to_field(seed)`
* `(ProverParams, VerifierParams, PoK) = generate(r)`
* output `(ProverParams.serialize | VerifierParams.serialize, PoK.serialize)`


``` rust
// receive a current set of parameters, a new set of parameters with PoK
// verify the PoK, verify the new set of parameters
// output the new parameters
fn param_update<Blob: AsRef<[u8]>>(
    cur_pp: Blob
    new_pp: Blob
    new_pp_pok: Blob,
) -> Blob;
```

Steps:
* deserialize `cur_pp` as `cur_prover` and `cur_verifier`
* deserialize `new_pp` as `new_prover` and `new_verifier`
* deserialize `new_pp_pok` as `pok`
* (optional) check `consistent(cur_prover, cur_verifier)`
* check `consistent(new_prover, new_verifier)`
* `checkpok(pok)`
* generate new parameter sets, and serialize it
