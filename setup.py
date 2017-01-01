#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# vim: fenc=utf-8
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
#
#

from setuptools import setup, find_packages
from os import path

here = path.abspath(path.dirname(__file__))
f = path.join(here, 'README.md')

setup(
    name='pymobiledevice',
    version='0.1.7',
    description="Interface with iOS devices",
    url='https://github.com/iOSForensics/pymobiledevice',
    author='gotohack',
    author_email='dark[-at-]gotohack.org',
    license='GPL',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2.7',
        #'Programming Language :: Python :: 3',
    ],

    keywords='pymobiledevice ios iphone ipad ipod',
    packages=find_packages(),
    py_modules=['pymobiledevice'],
    entry_points='',
    install_requires=[
        'construct',
        'm2crypto',
    ],
    #extras_require={
    #    'python_version >= "3"': [
    #        'ak-vendor',
    #    ],
    #    'dev': [''],
    #    'test': [''],
    #},
)
