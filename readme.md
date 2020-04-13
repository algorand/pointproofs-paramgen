# Pointproofs vector commitment parameter generation
[![Build Status](https://travis-ci.com/algorand/pointproofs-paramgen.svg?branch=master)](https://travis-ci.com/algorand/pointproofs-paramgen)

## Usage

This crate generates parameters for [Pointproofs](https://github.com/algorand/pointproofs) vector commitment schemes.

```
init params.out parameter_n
```
Generate starting parameters (with no entropy) for `parameter_n` and stores them in `params.out`.


```
evolve id_string params.in params.out
```
Reads old params from `params.in`, rerandomizes them and writes them (with a proof of knowledge of the mixed-in exponent) to `params.out`, using `id_string` as your identity.


```
verify id_string params.old params.new
```
Given assumed-good old params and a newly rerandomized version (with a proof of knowledge of the mixed-in exponent), verify that the new parameters were rerandomized correctly (i.e., check that the parameters are self-consistent and that the proof is correct for prover identity `id_string`).

```
finalize beacon_value params.in params.final
```
Given assumed-good params in `params.in` and the value of the shared random beacon, output the final set of parameters to `params.final`.

## Sample param

A sample file `crs.param` is provided for testing purpose. It supports vectors
of dimensions = 8. This file shall __NOT__ be used in products.
