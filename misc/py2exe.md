# Building Windows executable (exe)

Below is the snippet, which shows how to build exe from python code  
This method tested on Windows 10, 11  
Requires module py2exe 0.13.0.0+  

`options['includes']` Here you specify which modules to include. It will vary depending on your script. General rule - try to build, read errors which modules are missing, include them, build once again. After building - try to run and check for errors for missing modules, if any include them and rebuild.

```python
from py2exe import freeze
import shutil
import os

out_dir = "path/for/output"
if os.path.exists(out_dir):
    shutil.rmtree(out_dir)

freeze(
    console=['path/to/your/python/scritps.py'],
    windows=[],
    data_files=None,
    zipfile='library.zip',
    options={
        'includes': [ 
            'sys',
            'pymobiledevice3',
            'pygments.lexers.python',
            'pygments.lexers.data',
            'charset_normalizer',
            'jinxed.terminfo.vtwin10',
            'pyreadline3',
        ],
        'dist_dir': out_dir
    },
    version_info={}
)
```