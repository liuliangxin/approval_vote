@echo off
go build -o main.exe main.go

rem 
if not exist "logs" mkdir logs

for /f "usebackq delims=" %%L in ("filesks1.txt") do (
    if not "%%L"=="" (
        echo [node] start %%L
        rem 
        start /b main.exe %%L >> "logs\%%L.log" 2>&1
    )
)
rem 
:loop
timeout /t 60 >nul
goto loop