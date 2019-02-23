# cython: language_level=3

import cython
import hmac
import math
import hashlib


cdef class cFFX:

    cdef bytes secret
    cdef int radix
    cdef int rounds
    cdef str digestmod
    cdef public int maxlen

    def __init__(self, bytes secret, int radix, int rounds=10, str digestmod='sha1'):

        if rounds % 2 != 0:
            raise ValueError(f'rounds must be even, got {rounds}.')

        if rounds < 0 or rounds > 254:
            raise ValueError(f'rounds must be in range(2, 255), got {rounds}.')

        if radix > 255 or radix <= 1:
            raise ValueError(f'radix must be in range(2, 226), got {radix}.')

        self.secret = secret if secret is not None else b''
        self.radix = radix
        self.rounds = rounds
        self.digestmod = digestmod
        self.maxlen = int(hashlib.new(digestmod).digest_size * math.log(256, self.radix))


    @cython.boundscheck(False)
    @cython.nonecheck(False)
    cdef bytearray add(self, const unsigned char[:] a, const unsigned char[:] b):

        cdef int N = a.shape[0]
        cdef int k
        cdef bytearray res = bytearray(N)

        for i in range(N):

            k = (a[i] + b[i]) % self.radix
            res[i] = k

        return res


    @cython.boundscheck(False)
    @cython.nonecheck(False)
    cdef bytearray sub(self, const unsigned char[:] a, const unsigned char[:] b):

        cdef int N = a.shape[0]
        cdef int k
        cdef bytearray res = bytearray(N)

        for i in range(N):

            k = (a[i] - b[i]) % self.radix
            res[i] = k

        return res


    @cython.boundscheck(False)
    @cython.nonecheck(False)
    cdef bytearray rr(self, int i, bytearray s, int n):

        cdef bytes msg = (i).to_bytes(1, 'big') + s
        cdef bytearray res = bytearray(n)
        cdef int j, r
        cdef bytes h

        h = hmac.digest(self.secret, msg, 'sha1')
        d = int(h.hex(), 16)

        for j in range(n):
            d, r = divmod(d, self.radix)
            res[j] = r

        return res


    @cython.boundscheck(False)
    @cython.nonecheck(False)
    cdef tuple split(self, const unsigned char[:] data):
        cdef int N = data.shape[0]
        cdef int s = N // 2
        return bytearray(data[:s]), bytearray(data[s:])


    @cython.nonecheck(False)
    def encrypt(self, const unsigned char[:] data not None):

        cdef int N = data.shape[0]

        if N > self.maxlen:
            raise ValueError(f'Message length cannot exceed {self.maxlen} bytes.')

        cdef bytearray a, b, c
        a, b = self.split(data)

        for i in range(self.rounds):
            c = self.add(a, self.rr(i, b, len(a)+1))
            a, b = b, c

        a.extend(b)
        return bytes(a)


    @cython.nonecheck(False)
    def decrypt(self, const unsigned char[:] data not None):

        cdef int N = data.shape[0]

        if N > self.maxlen:
            raise ValueError(f'Message length cannot exceed {self.maxlen} bytes.')

        cdef bytearray a, b, c
        a, b = self.split(data)

        for i in range(self.rounds - 1, -1, -1):
            b, c = a, b
            a = self.sub(c, self.rr(i, b, len(a)+1))

        a.extend(b)
        return bytes(a)
