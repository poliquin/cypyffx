Formatting Preserving Encryption in Cython
==========================================

An implementation of format-preserving Feistel-based encryption (FFX)
in Cython, heavily inspired by [pyffx][pyffx].

Intended to work with Python 3.7 and Cython 0.29.


## Example

```python

>>> import cypyffx

>>> e = cypyffx.IntegerFFX(b'secret-key', length=4)
>>> e.encrypt(1234)
5648
>>> e.decrypt(5648)
1234

```

The above shows usage of the IntegerFFX class for encrypting numbers.
More generally, the module can work on any `bytes` object and returns
another `bytes` object...

```python

>>> ffx = cypyffx.cFFX(b'secret-key', radix=255, rounds=10, digestmod='sha1')
>>> ffx.encrypt(b'hello world')
b'\x10H(U\x8fR=\x8e\x9b\xbd\xf4'

```


## Limitations

The maximum radix (alphabet length) is 255 because the method operates on
arrays of bytes. What the values of those bytes mean is up to you. The
`IntegerFFX` class shows how to map bytes 0-9 with the decimal digits for
encrypting and decrypting integers. A similar class could be constructed for
any alphabet.

Note that because the alphabet is limited to 255 characters, this method
will not work with arbitrary Unicode strings. You can pass any bytes to
`cFFX.encrypt` that you want, but are not guaranteed to get back a sequence
of bytes that represents a valid string for a given multi-byte character
encoding.

The length of encoded values is limited by the digest method and length of
the alphabet. By default, sha1 is used and the maximum integer "length" is
48 decimal digits. With sha256, the maximum length is 77 decimal digits.

This module is really intended for fast encryption of short messages. For
example, it is well-suited to encrypting credit card and social security
numbers.


[pyffx]: https://github.com/emulbreh/pyffx
