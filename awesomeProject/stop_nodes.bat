@echo off

rem 查找所有运行中的 main.exe 进程并终止
for /f "tokens=2" %%i in ('tasklist ^| findstr "main.exe"') do (
    echo Killing process with PID: %%i
    taskkill /PID %%i /F
)

echo All nodes have been stopped.
pause
