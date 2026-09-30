# Third-party notices

ARGUS bundles the packages below. This file is generated from the
installed environment, not maintained by hand, so it reflects what is
actually shipped.

## Why ARGUS is GPL-3.0

ARGUS is licensed GPL-3.0-or-later (see `LICENSE`), and that is not an
arbitrary choice.

`piper-tts` provides the speech synthesis and is **GPL-3.0-or-later**,
because Piper links espeak-ng for phonemisation. The packaged
`ARGUS.exe` contains it. Distributing that binary therefore carries
GPL obligations regardless of what the rest of the source said, so the
project adopts the same licence rather than shipping a binary whose
terms differ from its repository.

**PyInstaller (GPL-2.0) is not a factor.** Its licence carries an
explicit exception permitting applications frozen with it to be
distributed under any terms. It is a build tool and is not part of the
shipped program.

### Copyleft components actually bundled

| package | version | licence |
|---|---|---|
| `piper-tts` | 1.7.0 | **GPL-3.0-or-later** |
| `pyinstaller` | 6.22.2 | **GNU General Public License v2 (GPLv2)** |

## All bundled dependencies

| package | version | licence |
|---|---|---|
| `comtypes` | 1.4.16 | see project |
| `ddgs` | 9.15.0 | see project |
| `fastapi` | 0.141.1 | see project |
| `faster-whisper` | 1.2.1 | MIT |
| `keyboard` | 0.13.5 | MIT |
| `numpy` | 2.5.2 | see project |
| `openwakeword` | 0.6.0 | Apache Software License |
| `pillow` | 12.3.0 | see project |
| `piper-tts` | 1.7.0 | GPL-3.0-or-later |
| `plyer` | 2.1.0 | MIT |
| `psutil` | 7.2.2 | BSD-3-Clause |
| `pycaw` | 20251023 | see project |
| `pydantic` | 2.13.4 | see project |
| `PyGetWindow` | 0.0.9 | BSD |
| `pyinstaller` | 6.22.2 | GNU General Public License v2 (GPLv2) |
| `pyperclip` | 1.11.0 | BSD |
| `pywebview` | 6.2.1 | BSD License |
| `pywin32` | 312 | PSF |
| `requests` | 2.34.2 | Apache-2.0 |
| `screen_brightness_control` | 0.27.2 | MIT |
| `sounddevice` | 0.5.6 | see project |
| `uvicorn` | 0.52.4 | see project |
| `yt-dlp` | 2026.8.19 | see project |

## Models and data

- **Whisper** speech models are downloaded at first run from Hugging
  Face and are subject to their own licences (MIT for the OpenAI
  Whisper weights).
- **Piper** voice models (`.onnx`) carry the licence stated by each
  voice; the bundled `en_GB-alan-medium` voice is from the Piper
  project.
- **Ollama** is a separate application that ARGUS talks to over HTTP.
  It is neither bundled nor distributed here.
- **Groq** and **Google Gemini** are optional network services used
  only when you configure an API key. No key is included.
