
from .cyffx import cFFX


class IntegerFFX:

    def __init__(self, secret, length, rounds=10, digestmod='sha1'):
        """Formatting preserving encryption for integers.

        Args:
            secret (bytes): encryption and decryption key.
            length (int): length of integers to be encrypted.

        Kwargs:
            rounds (int): number of Feistel rounds to use for encryption.
            digestmod (str): hash method to use for block cipher.
        """

        if not isinstance(secret, bytes):
            raise TypeError(f'secret must be type bytes, not {type(secret)}.')

        self.secret = secret
        self.rounds = int(rounds)
        self.digestmod = digestmod

        self.alphabet = '0123456789'
        self.packdict = {k: v for v, k in enumerate(self.alphabet)}

        self._ffx = cFFX(
            self.secret,
            len(self.alphabet),
            self.rounds,
            self.digestmod
        )

        self.length = int(length)

        if self.length > self._ffx.maxlen:
            raise ValueError(
                f'digest {self.digestmod} has maximum length {self.length} for integers'
            )


    def _pack(self, value):
        """Convert value to bytearray for encryption."""

        packed = bytearray(self.length)

        for i, v in enumerate('{value:0{}d}'.format(self.length, value=value)):
            packed[i] = self.packdict[v]

        return packed


    def _unpack(self, packed):
        """Convert encoded byte value back to an integer."""

        return int(''.join(self.alphabet[i] for i in packed))


    def encrypt(self, value):
        """Encrypt an integer value."""

        byteval = self._pack(value)
        encoded = self._ffx.encrypt(byteval)
        return self._unpack(encoded)


    def decrypt(self, value):
        """Decrypt an integer value."""

        byteval = self._pack(value)
        decoded = self._ffx.decrypt(byteval)
        return self._unpack(decoded)
