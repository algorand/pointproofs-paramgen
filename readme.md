# vector commitment parameter generation
[![Build Status](https://travis-ci.com/algorand/veccom-paramgen.svg?token=cs332z4omsgc9ykLW8pu&branch=master)](https://travis-ci.com/algorand/veccom-paramgen)

## Usage

This crate generates parameters for [vector commitment](https://github.com/algorand/veccom-rust) schemes.

```
generate params.out ciphersuite_ID parameter_n
```
Generate a parameter set for `ciphersuite_ID` and `parameter_n`, serialized, and stored in `params.out`.


```
evolve param.in param.out
```
Reads old params from `params.in`, rerandomizes them and writes them (with a proof of knowledge of the mixed-in exponent) to `params.out`


```
verify params.old params.new
```
Given assumed-good old params and a newly rerandomized version (with a proof of knowledge of the mixed-in exponent), verify that the new parameters were rerandomized correctly (i.e., check that the parameters are self-consistent and that the proof is correct).
