import logging
import os
import site
import sys
from pathlib import Path

import coloredlogs
import PyInstaller.__main__

import pymobiledevice3.__main__
import pymobiledevice3.cli
import pymobiledevice3.resources

coloredlogs.install(level=logging.DEBUG)

ROOT = Path(__file__).parent.parent.parent
DEFAULT_OUTPUT = ROOT / Path('dist/__main__').with_suffix('.exe' if sys.platform == 'win32' else '')
OUTPUT = (ROOT / 'dist/pymobiledevice3').with_suffix('.exe' if sys.platform == 'win32' else '')


def main() -> None:
    site_packages_path = site.getsitepackages()[0]
    resources_dir = Path(pymobiledevice3.resources.__file__).parent
    pymobiledevice3_cli_path = Path(pymobiledevice3.cli.__file__).parent

    hidden_imports = []

    for module in pymobiledevice3_cli_path.iterdir():
        if module.name.endswith('.py') and module.name != '__init__.py':  # Avoid including the __init__.py
            # Create the module name to be added to hidden imports
            module_name = 'pymobiledevice3.cli.' + os.path.splitext(module.name)[0]
            hidden_imports.append('--hidden-import=' + module_name)

    pyinstaller_args = [
        pymobiledevice3.__main__.__file__,
        '--hidden-import=ipsw_parser',
        '--hidden-import=zeroconf',
        '--hidden-import=pyimg4',
        '--hidden-import=zeroconf._utils.ipaddress',
        '--hidden-import=zeroconf._handlers.answers',
        '--hidden-import=readchar',
        '--copy-metadata=pyimg4',
        '--copy-metadata=readchar',
        '--copy-metadata=apple_compress',
        '--onefile',
    ]
    if sys.platform == 'win32':
        pyinstaller_args.extend([
            '--add-binary', f'{site_packages_path}/Lib/site-packages/pytun_pmd3/wintun/*;pytun_pmd3/wintun/bin',
            '--add-binary', f'{resources_dir}/webinspector;pymobiledevice3/resources/webinspector',
        ])
    else:
        pyinstaller_args.extend([
            '--add-binary', f'{site_packages_path}/pytun_pmd3:pytun_pmd3',
            '--add-binary', f'{resources_dir}/webinspector:pymobiledevice3/resources/webinspector',
        ])
    pyinstaller_args.extend(hidden_imports)
    PyInstaller.__main__.run(pyinstaller_args)
    DEFAULT_OUTPUT.rename(OUTPUT)


if __name__ == '__main__':
    main()
