@echo off
setlocal
if not exist "%~dp0nodepure.exe" (
  echo Build first: go build -trimpath -o nodepure.exe ./cmd/server
  exit /b 1
)
if not defined NODEPURE_TEMP_DIR (
  if not exist "%~dp0.nodepure-tmp" (
    mkdir "%~dp0.nodepure-tmp"
    if errorlevel 1 exit /b 1
    icacls "%~dp0.nodepure-tmp" /inheritance:r /grant:r "%USERDOMAIN%\%USERNAME%:(OI)(CI)F" >nul
    if errorlevel 1 (
      echo Cannot protect the temporary directory. Set NODEPURE_TEMP_DIR to a private writable directory.
      exit /b 1
    )
  )
  set "NODEPURE_TEMP_DIR=%~dp0.nodepure-tmp"
)
if not defined MIHOMO_BIN set "MIHOMO_BIN=%~dp0bin\mihomo.exe"
pushd "%~dp0"
"%~dp0nodepure.exe"
set "nodepure_exit=%ERRORLEVEL%"
popd
exit /b %nodepure_exit%
