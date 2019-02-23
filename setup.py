
from setuptools import setup, Extension
from Cython.Distutils import build_ext


extensions = [
    Extension('cypyffx.cyffx', ['cypyffx/cyffx.pyx'])
]


setup(
    name = 'Format preserving encyption',
    install_requires = ['cython'],
    packages = ['cypyffx'],
    cmdclass = {'build_ext': build_ext},
    ext_modules = extensions
)
