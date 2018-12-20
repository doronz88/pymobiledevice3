# -*- coding: utf-8 -*-
'''package script
'''


import os
import platform
import sys
from setuptools import setup, find_packages
  
BASE_DIR = os.path.realpath(os.path.dirname(__file__))
VERSION = "1.0.2"
  
def replace_version_py(version):
    content = """# -*- coding: utf-8 -*-
'''pymobiledevice-qta版本
'''
VERSION = '%(version)s' 
"""
    version_py = os.path.join(BASE_DIR, 'pymobiledevice', 'version.py')
    with open(version_py, 'w') as fd:
        fd.write(content % {'version':version})
  

def generate_version():
    version = VERSION
    if os.path.isfile(os.path.join(BASE_DIR, "version.txt")):
        with open("version.txt", "r") as fd:
            content = fd.read().strip()
            if content:
                version = content
    replace_version_py(version)
    return version


def parse_requirements():
    reqs = []
    if os.path.isfile(os.path.join(BASE_DIR, "requirements.txt")):
        with open(os.path.join(BASE_DIR, "requirements.txt"), 'r') as fd:
            for line in fd.readlines():
                line = line.strip()
                if line:
                    reqs.append(line)
    if sys.platform == "win32":
        if "64" in platform.architecture()[0]:
            reqs.append('M2CryptoWin64')
        else:
            reqs.append('M2CryptoWin32')
    return reqs


def get_description():
    with open(os.path.join(BASE_DIR, "README.md"), "r") as fh:
        return fh.read()


if __name__ == "__main__": 
    
    setup(
        version=generate_version(),
        name="pymobiledevice-qta",
        description="python implementation for libimobiledevice library",
        long_description=get_description(),
        long_description_content_type='text/markdown',
        cmdclass={},
        packages=find_packages(),
        package_data={'':['*.txt', '*.TXT'], },
        data_files=[(".", ["requirements.txt"])],
        author="QTA",
        license="Copyright(c)2010-2018 Tencent All Rights Reserved. ",
        install_requires=parse_requirements(),
        entry_points={},
        classifiers=[
            "Programming Language :: Python :: 2.7",
            "Programming Language :: Python :: 3.6",
            "Programming Language :: Python :: 3.7",
        ],
        url="https://github.com/qtacore/pymobiledevice",
        project_urls={
            "pymobiledevice-qta Documentation":"https://github.com/qtacore/pymobiledevice"
        },
    )
