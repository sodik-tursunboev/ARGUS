# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

datas = [('C:/ARGUS/argus-os/intent.py', '.'), ('C:/ARGUS/argus-os/hud-v2/dist/index.html', 'hud-v2/dist'), ('C:/ARGUS/argus-os/hud-v2/dist/assets/argus-waking.mp4', 'hud-v2/dist/assets'), ('C:/ARGUS/argus-os/hud-v2/dist/assets/core-alert.jpg', 'hud-v2/dist/assets'), ('C:/ARGUS/argus-os/hud-v2/dist/assets/core-idle.jpg', 'hud-v2/dist/assets'), ('C:/ARGUS/argus-os/hud-v2/dist/assets/index-CBlPdhRD.css', 'hud-v2/dist/assets'), ('C:/ARGUS/argus-os/hud-v2/dist/assets/index-D1XFocNJ.js', 'hud-v2/dist/assets'), ('C:/ARGUS/argus-os/hud-v2/dist/assets/splash.png', 'hud-v2/dist/assets'), ('C:/ARGUS/argus-os/voices', 'voices'), ('C:/ARGUS/argus-os/skills', 'skills'), ('C:/ARGUS/argus-os/tools/harden_acls.ps1', 'tools')]
binaries = []
hiddenimports = ['uvicorn.logging', 'uvicorn.loops.auto', 'uvicorn.loops.asyncio', 'uvicorn.protocols.http.auto', 'uvicorn.protocols.http.h11_impl', 'uvicorn.protocols.http.httptools_impl', 'uvicorn.protocols.websockets.auto', 'uvicorn.protocols.websockets.websockets_impl', 'uvicorn.protocols.websockets.wsproto_impl', 'uvicorn.lifespan.on', 'uvicorn.lifespan.off', 'h11', 'anyio', 'sniffio', 'comtypes', 'pycaw', 'pygetwindow', 'plyer.platforms.win.notification', 'security', 'paths', 'brain', 'intent', 'router', 'listener', 'tts', 'ollama_client', 'ipc', 'stt_worker', 'tts_worker', 'settings', 'faceauth', 'threatmon', 'threatmon.persistence', 'threatmon.privacy', 'threatmon.netconfig', 'skills.cleanup_skill']
tmp_ret = collect_all('faster_whisper')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('openwakeword')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('onnxruntime')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('ctranslate2')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('piper')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('webview')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('tokenizers')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('uvicorn')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('tzdata')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('cv2')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]


a = Analysis(
    ['C:/ARGUS/argus-os/argus.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)
splash = Splash(
    'C:/ARGUS/argus-os/hud-v2/dist/assets/splash.png',
    binaries=a.binaries,
    datas=a.datas,
    text_pos=None,
    text_size=12,
    minify_script=True,
    always_on_top=True,
)

exe = EXE(
    pyz,
    a.scripts,
    splash,
    [],
    exclude_binaries=True,
    name='ARGUS',
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
    uac_admin=True,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    splash.binaries,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='ARGUS',
)
