@echo off
REM import_responses.bat — Split AI's combined response into individual CVE JSON files
REM Usage: import_responses.bat [repo_name] [path\to\response_file.txt]
REM Example: import_responses.bat CyberTrace
REM          import_responses.bat CyberTrace C:\Users\you\Downloads\ai_response.txt

setlocal enabledelayedexpansion

set REPO=%1
set RESPONSES_FILE=%2

if "%REPO%"=="" (
    for /f "delims=" %%d in ('dir /b /ad /o-d data\ 2^>nul') do (
        if "!REPO!"=="" set REPO=%%d
    )
)
if "%REPO%"=="" (
    echo Usage: import_responses.bat ^<repo_name^> [response_file]
    exit /b 1
)

set RESPONSES_DIR=data\%REPO%\responses
if not exist "%RESPONSES_DIR%" mkdir "%RESPONSES_DIR%"

REM If no file provided, open Windows file picker via PowerShell
if "%RESPONSES_FILE%"=="" (
    echo [sage] Select the AI response file...
    for /f "delims=" %%f in ('powershell -NoProfile -Command ^
        "Add-Type -AssemblyName System.Windows.Forms; ^
        $d = New-Object System.Windows.Forms.OpenFileDialog; ^
        $d.Title = 'Select AI response file'; ^
        $d.Filter = 'Text files (*.txt)|*.txt|All files (*.*)|*.*'; ^
        $d.InitialDirectory = [Environment]::GetFolderPath('UserProfile') + '\Downloads'; ^
        if ($d.ShowDialog() -eq 'OK') { $d.FileName } else { '' }"') do (
        set RESPONSES_FILE=%%f
    )
)

if "%RESPONSES_FILE%"=="" (
    echo [sage] No file selected.
    exit /b 1
)

if not exist "%RESPONSES_FILE%" (
    echo [sage] File not found: %RESPONSES_FILE%
    exit /b 1
)

echo [sage] Parsing %RESPONSES_FILE% ...

python3 -c "
import sys, re, json, pathlib

responses_file = pathlib.Path(r'%RESPONSES_FILE%')
responses_dir  = pathlib.Path(r'%RESPONSES_DIR%')

text = responses_file.read_text(encoding='utf-8')

pattern = re.compile(
    r'===\s*(CVE-[\w-]+)\s*===\s*\n([\s\S]*?)(?====\s*CVE-|$)',
    re.IGNORECASE
)

saved = 0
errors = 0

for match in pattern.finditer(text):
    cve_id   = match.group(1).strip()
    raw_json = match.group(2).strip()
    raw_json = re.sub(r'^[\x60]{3}(?:json)?\s*', '', raw_json)
    raw_json = re.sub(r'\s*[\x60]{3}$', '', raw_json).strip()
    brace_match = re.search(r'\{[\s\S]*\}', raw_json)
    if not brace_match:
        print(f'  [!] {cve_id} -- no JSON found, skipping')
        errors += 1
        continue
    try:
        data = json.loads(brace_match.group(0))
    except json.JSONDecodeError as e:
        print(f'  [!] {cve_id} -- invalid JSON: {e}')
        errors += 1
        continue
    out_path = responses_dir / f'{cve_id}.json'
    out_path.write_text(json.dumps(data, indent=2))
    status = 'vulnerable' if data.get('vulnerable') else 'clean'
    conf = data.get('confidence', 0)
    print(f'  OK  {cve_id}  [{status}]  confidence={conf:.0%}')
    saved += 1

print(f'')
print(f'[sage] Saved {saved} response(s)  |  {errors} error(s)')
"

echo.
echo ========================================================
echo   Next step: re-run the pipeline
echo   python3 main.py --synapse path\to\%REPO%
echo ========================================================

endlocal
