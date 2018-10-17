# -*- coding: utf-8 -*-
'''package script
'''


import os
from setuptools import setup, find_packages
  
BASE_DIR = os.path.realpath(os.path.dirname(__file__))

  
def generate_version():
    version = "0.1.10"
    if os.path.isfile(os.path.join(BASE_DIR, "version.txt")):
        with open("version.txt", "r") as fd:
            content = fd.read().strip()
            if content:
                version = content
    return version


def parse_requirements():
    reqs = []
    if os.path.isfile(os.path.join(BASE_DIR, "requirements.txt")):
        with open(os.path.join(BASE_DIR, "requirements.txt"), 'r') as fd:
            for line in fd.readlines():
                line = line.strip()
                if line:
                    reqs.append(line)
    return reqs


if __name__ == "__main__": 
    
    setup(
        version=generate_version(),
        name="pymobiledevice2",
        cmdclass={},
        packages=find_packages(),
        package_data={'':['*.txt', '*.TXT'], },
        data_files=[(".", ["requirements.txt", "version.txt"])],
        author="Tencent",
        license="Copyright(c)2010-2018 Tencent All Rights Reserved. ",
        install_requires=parse_requirements(),
        entry_points={}
    )