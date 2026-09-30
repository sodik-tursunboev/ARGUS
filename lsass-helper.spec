# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['C:/ARGUS/argus-os/threatmon/lsass_agent.py'],
    pathex=[],
    binaries=[],
    datas=[('C:/ARGUS/argus-os/threatmon/lsass.py', 'threatmon'), ('C:/ARGUS/argus-os/threatmon/lsass_peer.py', 'threatmon')],
    hiddenimports=['psutil'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='lsass-helper',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='lsass-helper',
)
