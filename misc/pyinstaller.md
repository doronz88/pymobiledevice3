# Building Windows executable (exe)

Below is the snippet, which shows how to build exe from python code  
This method tested on Windows 10, 11  
Requires module pyinstaller 6.2.0+  

```python
import shutil
import os
import site

import PyInstaller.__main__

site_packages_path = site.getsitepackages()[1]
out_dir = "path/for/output"
if os.path.exists(out_dir):
    shutil.rmtree(out_dir)


PyInstaller.__main__.run([
    'path/to/file.py',
    '--hidden-import=ipsw_parser',
    '--hidden-import=zeroconf',
    '--hidden-import=pyimg4',
    '--hidden-import=apple_compress',
    '--hidden-import=zeroconf._utils.ipaddress',
    '--hidden-import=zeroconf._handlers.answers',
    '--hidden-import=readchar',
    '--copy-metadata=pyimg4',
    '--copy-metadata=readchar',
    '--copy-metadata=apple_compress',
    '--add-binary', f"{site_packages_path}/pytun_pmd3/*;pytun_pmd3",
    '--onefile'
])

shutil.move('dist', 'path/for')
```
