# constbn - a constant time Golang BigNum library

This is an implementation of bignums with a focus on constant time operations. Unless anything else is mentioned, all
operations are constant time. The initial implementation is based on the i31 implementation from BearSSL. It uses uint32
values as the limbs, but only 31 bits are actually used.

The main goal of this implementation is to make it possible to have a generic constant time modular exponentiation
operation on bignums large enough to implement modern cryptographyic algorithms, since the Golang big/int library is not
constant time. Other operations might be added with time, making this a more generic library, but the focus is initially
to serve the needs of the otr3 project.


## Security and assumptions

- The code in this library assumes that the uint32 multiplication routines are constant time on the machine in question.

## Authors

- Centro de Autonomía Digital


## License

This project is licensed under the GNU GENERAL PUBLIC LICENSE VERSION 3.0.
