# -*- coding: utf-8 -*-
'''package script
'''


import os
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
    return reqs



if __name__ == "__main__": 
    
    setup(
        version=generate_version(),
        name="pymobiledevice-qta",
        long_description="""
# pymobiledevice

pymobiledevice is a cross-platform implementation of the mobiledevice library 
that talks the protocols to support iPhone®, iPod Touch®, iPad® and Apple TV® devices.
""",
        long_description_content_type='text/markdown',
        cmdclass={},
        packages=find_packages(),
        package_data={'':['*.txt', '*.TXT'], },
        data_files=[(".", ["requirements.txt"])],
        author="QTA",
        license="Copyright(c)2010-2018 Tencent All Rights Reserved. ",
        install_requires=parse_requirements(),
        entry_points={}
    )
