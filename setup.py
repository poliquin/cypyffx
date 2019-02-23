
from setuptools import setup, Extension
from Cython.Distutils import build_ext


extensions = [
    Extension('cypyffx.cyffx', ['cypyffx/cyffx.pyx'])
]


setup(
    name = 'cypyffx',
    version = '0.1.0',
    description = 'Format preserving encyption',
    packages = ['cypyffx'],
    install_requires = ['cython'],
    cmdclass = {'build_ext': build_ext},
    ext_modules = extensions,
    author = 'Chris Poliquin',
    author_email = 'chrispoliquin@gmail.com',
    url = 'https://github.com/poliquin/cypyffx',
    keywords = ['ffx', 'anonymization', 'encyption', 'crypto'],
    classifiers = [
        'Programming Language :: Python :: 3',
        'Programming Language :: Cython',
        'Operating System :: OS Independent',
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Utilities',
        'Topic :: Security :: Cryptography'
    ]
)
