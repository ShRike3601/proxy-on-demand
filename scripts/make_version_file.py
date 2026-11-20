"""Write version_info.txt for PyInstaller (--version-file), so ProxyOnDemand.exe carries its product
name and version in Windows' file properties. Code signing (SignPath) requires these to be set.
Run from the repository root: python scripts/make_version_file.py"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from proxy_app import __version__  # noqa: E402

nums = tuple(int(x) for x in __version__.split(".")) + (0,)
fields = {
    "CompanyName": "ShRike3601",
    "FileDescription": "Proxy on demand",
    "FileVersion": __version__,
    "InternalName": "ProxyOnDemand",
    "LegalCopyright": "Copyright (c) 2026 ShRike3601. MIT License.",
    "OriginalFilename": "ProxyOnDemand.exe",
    "ProductName": "Proxy on demand",
    "ProductVersion": __version__,
}
strings = ",\n        ".join(f"StringStruct('{k}', '{v}')" for k, v in fields.items())
with open("version_info.txt", "w", encoding="utf-8") as f:
    f.write(f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers={nums}, prodvers={nums}, mask=0x3f, flags=0x0, OS=0x40004,
                    fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
        {strings}])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
""")
print(f"version_info.txt written for {__version__}")
