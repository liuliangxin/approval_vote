@echo off
go build -o main.exe main.go

rem 确保日志目录存在
if not exist "logs" mkdir logs

for /f "usebackq delims=" %%L in ("filesks1.txt") do (
    if not "%%L"=="" (
        echo [node] start %%L
        rem 将每个节点的输出重定向到 logs/nodeID.log 文件
        start /b main.exe %%L >> "logs\%%L.log" 2>&1
    )
)
rem 无限等待，让 cmd 窗口保持开启
:loop
timeout /t 60 >nul
goto loop