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

## Security notes

* The "evolve" operation is NOT CONSTANT TIME and should not be run in a setting where an attacker can precisely measure runtime.

* [consistencycheck.pdf](./consistencycheck.pdf) contains a description and security proof for the probabilistic consistency check used as part of the `verify` operation.

* [usage.md](./usage.md) describes how to carry out a secure multiparty computation to generate parameters using this tool.

* [security.pdf](./security.pdf) gives a security proof of said multiparty protocol.

* This code is NOT production ready yet. It passed one external audit, but additional auditing and testing is required before deployment.
