@echo off
REM export_prompts.bat — Bundle all pending CVE prompts into one file for AI review
REM Usage: export_prompts.bat [repo_name]
REM Example: export_prompts.bat CyberTrace

setlocal enabledelayedexpansion

set REPO=%1
if "%REPO%"=="" (
    for /f "delims=" %%d in ('dir /b /ad /o-d data\ 2^>nul') do (
        if "!REPO!"=="" set REPO=%%d
    )
)
if "%REPO%"=="" (
    echo Usage: export_prompts.bat ^<repo_name^>
    echo Example: export_prompts.bat CyberTrace
    exit /b 1
)

echo [sage] Repo: %REPO%

set PROMPTS_DIR=data\%REPO%\prompts
set RESPONSES_DIR=data\%REPO%\responses
set OUT_FILE=data\%REPO%\all_prompts.txt

if not exist "%PROMPTS_DIR%" (
    echo [sage] No prompts directory found at %PROMPTS_DIR%
    echo        Run: python main.py --repo path\to\%REPO% --days 7
    exit /b 1
)

if not exist "%RESPONSES_DIR%" mkdir "%RESPONSES_DIR%"

python3 - "%PROMPTS_DIR%" "%RESPONSES_DIR%" "%OUT_FILE%" "%REPO%" << PYEOF
REM Delegate to Python for cross-platform reliability
PYEOF

python3 -c "
import sys, pathlib, os

prompts_dir   = pathlib.Path(r'%PROMPTS_DIR%')
responses_dir = pathlib.Path(r'%RESPONSES_DIR%')
out_file      = pathlib.Path(r'%OUT_FILE%')
repo          = '%REPO%'

header = '''You are a security vulnerability analyst. Below are multiple CVE analysis tasks.
For EACH CVE, respond with EXACTLY this format — no extra text, no markdown:

=== CVE-XXXX-XXXXX ===
{\"vulnerable\": true or false, \"confidence\": 0.0-1.0, \"reason\": \"one sentence\", \"affected_functions\": [\"fn1\"], \"attack_vector\": \"how attacker reaches it, or empty\", \"recommendation\": \"fix, or empty\"}

Analyze each CVE independently.
---

'''

pending = []
for f in sorted(prompts_dir.glob('CVE-*.txt')):
    resp = responses_dir / (f.stem + '.json')
    if not resp.exists():
        pending.append(f)

if not pending:
    print('[sage] No pending prompts — all responses already saved.')
    sys.exit(0)

print(f'[sage] Found {len(pending)} pending CVE(s) — bundling into {out_file}')

parts = [header]
for f in pending:
    parts.append('=' * 38)
    parts.append(f'TASK: {f.stem}')
    parts.append('=' * 38)
    parts.append(f.read_text(encoding='utf-8'))
    parts.append('')

out_file.write_text('\n'.join(parts), encoding='utf-8')
size = out_file.stat().st_size
print(f'[sage] Bundle written -> {out_file}')
print(f'[sage] Size: {size} bytes, {len(pending)} CVEs')
print()
print('=' * 56)
print('  Next steps:')
print(f'  1. Upload {out_file} to Claude / ChatGPT / Gemini')
print(f'  2. Save the AI response as:')
print(f'     data\\{repo}\\all_responses.txt')
print(f'  3. Run: import_responses.bat {repo}')
print('=' * 56)

os.startfile(str(out_file))
"

endlocal
