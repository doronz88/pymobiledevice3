# Building Windows executable (exe)

Below is the snippet, which shows how to build exe from python code  
This method tested on Windows 10, 11  
Requires module pyinstaller 6.2.0+  


```python
import shutil
import os

import PyInstaller.__main__


out_dir = "path/for/output"
if os.path.exists(out_dir):
    shutil.rmtree(out_dir)


PyInstaller.__main__.run([
    'path/to/file.py',
    '--hidden-import=ipsw_parser',
    '--hidden-import=zeroconf',
    '--hidden-import=pyimg4',
    '--hidden-import=zeroconf._utils.ipaddress',
    '--hidden-import=zeroconf._handlers.answers',
    '--copy-metadata=pyimg4',
    '--onefile'
])

shutil.move('dist', 'path/for')
```