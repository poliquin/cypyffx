
import hashlib
import math

import pytest

from cypyffx import IntegerFFX, cFFX


def test_integer_ffx_basics():
    """Test that encryption and decryption work for integers."""

    for length in (4, 8, 12, 16):
        for rounds in (8, 10, 12, 16):

            # chosen digest method can be anything available through hashlib
            # but message length might be restricted

            for digest in hashlib.algorithms_guaranteed:

                maxlen = int(
                    hashlib.new(digest).digest_size * math.log(256, 10)
                )
                if maxlen < length:
                    continue

                iffx = IntegerFFX(
                    b'secret-key',
                    length=length,
                    rounds=rounds,
                    digestmod=digest
                )

                # check that various integers can be encrypted and decrypted
                for value in range(10**(length-2), 10**(length-1), 10**(length-3)):

                    encoded = iffx.encrypt(value)
                    assert value == iffx.decrypt(encoded)


def test_ffx_config():
    """Check that reasonable parameters are accepted."""

    # rounds must be a positive, even decimal number
    with pytest.raises(ValueError):
        for i in range(3, 100, 2):
            cFFX(b'secret-key', radix=10, rounds=i)
            IntegerFFX(b'secret-key', length=10, rounds=i)

    # radix must be at least 2
    with pytest.raises(ValueError):
        for i in range(-2, 2):
            cFFX(b'secret-key', radix=i)
            # no test for IntegerFFX because radix is set by class

    # secret must be bytes
    with pytest.raises(TypeError):
        cFFX('secret-key', radix=10)
        IntegerFFX('secret-key', length=10)

    # messages are limited in size by the radix and hash function
    e = cFFX(b'secret-key', radix=10, digestmod='sha1')
    with pytest.raises(ValueError):
        e.encrypt(b'\x01'*9999)
        IntegerFFX(b'secret-key', length=9999, digestmod='sha1')

    # invalid hash functions should raise an error
    with pytest.raises(ValueError):
        cFFX(b'secret-key', radix=10, digestmod='foobar')
        IntegerFFX(b'secret-key', length=10, digestmod='foobar')
