@echo off
setlocal enabledelayedexpansion

rem commit-push.bat -- stage everything, commit, push the current branch.
rem
rem Usage:
rem   commit-push.bat                  (commit message: "Update <date> <time>")
rem   commit-push.bat "your message"   (custom commit message)
rem
rem Skips the commit step (but still pushes) if there is nothing staged --
rem safe to run repeatedly or on a schedule.

cd /d "%~dp0"

git rev-parse --is-inside-work-tree >nul 2>&1
if errorlevel 1 (
    echo Not a git repository: %cd%
    exit /b 1
)

for /f "delims=" %%b in ('git branch --show-current') do set BRANCH=%%b
if "%BRANCH%"=="" (
    echo Detached HEAD -- refusing to auto-commit. Check out a branch first.
    exit /b 1
)

set MSG=%~1
if "%MSG%"=="" (
    for /f "tokens=1-3 delims=/ " %%a in ("%date%") do set DATESTAMP=%%a-%%b-%%c
    set MSG=Update !DATESTAMP! %time:~0,8%
)

git add -A

git diff --cached --quiet
if errorlevel 1 (
    echo Committing on !BRANCH!: !MSG!
    git commit -m "!MSG!" -m "" -m "Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
    if errorlevel 1 (
        echo Commit failed.
        exit /b 1
    )
) else (
    echo Nothing staged -- skipping commit.
)

echo Pushing !BRANCH! to origin...
git push origin "!BRANCH!"
if errorlevel 1 (
    echo Push failed. If this is the first push of this branch, run:
    echo   git push -u origin !BRANCH!
    exit /b 1
)

echo Done.
endlocal
