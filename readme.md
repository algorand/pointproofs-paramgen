# Pointproofs vector commitment parameter generation
[![Build Status](https://travis-ci.com/algorand/pointproofs-paramgen.svg?branch=master)](https://travis-ci.com/algorand/pointproofs-paramgen)

## Usage

This crate generates parameters for [Pointproofs](https://github.com/algorand/pointproofs) vector commitment schemes.

```
init params.out parameter_n
```
Generate a parameter set for `parameter_n`, serialized, and stored in `params.out`.


```
evolve param.in param.out
```
Reads old params from `params.in`, rerandomizes them and writes them (with a proof of knowledge of the mixed-in exponent) to `params.out`


```
verify params.old params.new
```
Given assumed-good old params and a newly rerandomized version (with a proof of knowledge of the mixed-in exponent), verify that the new parameters were rerandomized correctly (i.e., check that the parameters are self-consistent and that the proof is correct).

## Sample param

A sample file `crs.param` is provided for testing purpose. It supports vectors
of dimensions = 8. This file shall __NOT__ be used in products.
