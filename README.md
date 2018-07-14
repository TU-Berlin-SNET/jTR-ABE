# jTR-ABE
Traceable and Revocable Attribute-based Encryption in Java

This software package implements an ABE scheme by Liu and Wong: [Practical Attribute-Based Encryption: Traitor Tracing, Revocation, and Large Universe](http://eprint.iacr.org/2014/616). The flavor is Ciphertext-Policy (CP-ABE).
The implementation supports non-monotonic access structures (AC), which is not part this scheme. We borrow techniques from Yamada et al. (http://eprint.iacr.org/2014/181) to achieve this property.

#### Notes

jTR-ABE is a rewrite of an early version of [JCPABE](https://github.com/TU-Berlin-SNET/JCPABE) which itself is a complete rewrite of an earlier Java [cpabe](https://github.com/junwei-wang/cpabe) implementation) which is a port of Bethencourt's [libbswabe](http://hms.isi.jhu.edu/acsc/cpabe/).

It supports

- Traceability of traitors (publishers of decryption keys or decryption boxes),
- User revocation,
- Policies with expressive threshold or boolean formulas and numerical attributes.

The main functionality is accessible in the trabe.Cpabe class.

This is research software and should not be used in application where actual security is required.

#### Dependencies
Download the source of JPBC from [here](http://sourceforge.net/p/jpbc/code/) (JCPABE has only been tested with version 2.0.0).
Install it into your local maven repository using
```sh
$ mvn install
```
(only the sub projects jpbc-plaf, jpbc-api and jpbc-pbc are needed)

It is also recommended to install the PBC wrapper for JPBC to improve the performance (as explained [here](http://gas.dia.unisa.it/projects/jpbc/docs/pbcwrapper.html)). Note: in Ubuntu the GMP dependency package is called libgmp10.


#### Build
To build jTR-ABE:
```sh
$ mvn compile
```

To install it into a local maven repository run:
```sh
$ mvn install
```


#### Common Problems

JPBC-PBC library can not be found or loaded:
Remove the system JNA library or patch JPBC to work with newest JNA.
