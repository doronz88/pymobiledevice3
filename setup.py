from pathlib import Path

from setuptools import setup, find_packages

BASE_DIR = Path(__file__).parent.resolve(strict=True)
VERSION = '1.29.0'
PACKAGE_NAME = 'pymobiledevice3'
PACKAGES = [p for p in find_packages() if not p.startswith('tests')]


def parse_requirements():
    reqs = []
    with open(BASE_DIR / 'requirements.txt', 'r') as fd:
        for line in fd.readlines():
            line = line.strip()
            if line:
                reqs.append(line)
    return reqs


def get_description():
    return (BASE_DIR / 'README.md').read_text()


if __name__ == '__main__':
    setup(
        version=VERSION,
        name=PACKAGE_NAME,
        description='Pure python3 implementation for working with iDevices (iPhone, etc...)',
        long_description=get_description(),
        long_description_content_type='text/markdown',
        cmdclass={},
        packages=PACKAGES,
        include_package_data=True,
        package_data={PACKAGE_NAME: ['resources/webinspector/*.js',
                                     'resources/dsc_uuid_map.json',
                                     'resources/notifications.txt']},
        author='DoronZ',
        author_email='doron88@gmail.com',
        license='GNU GENERAL PUBLIC LICENSE - Version 3, 29 June 2007',
        install_requires=parse_requirements(),
        entry_points={
            'console_scripts': ['pymobiledevice3=pymobiledevice3.__main__:cli',
                                ],
        },
        classifiers=[
            'Programming Language :: Python :: 3.7',
            'Programming Language :: Python :: 3.8',
            'Programming Language :: Python :: 3.9',
            'Programming Language :: Python :: 3.10',
        ],
        url='https://github.com/doronz88/pymobiledevice3',
        project_urls={
            'pymobiledevice3': 'https://github.com/doronz88/pymobiledevice3'
        },
        tests_require=['pytest', 'cmd2_ext_test'],
    )
