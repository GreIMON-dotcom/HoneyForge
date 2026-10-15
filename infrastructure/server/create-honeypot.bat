@echo off
setlocal
chcp 65001 >nul

set "SVC=%~1"
if "%SVC%"=="" set "SVC=telnet-shell"

set "SSH_CONFIG=%USERPROFILE%\.ssh\config.honeyforge"
if not exist "%SSH_CONFIG%" (
  echo Не найден файл доступа к серверу: "%SSH_CONFIG%"
  echo Сначала настройте доступ к серверу, затем запустите этот файл снова.
  pause
  exit /b 1
)

echo Тип ловушки: %SVC%
echo Соединение с сервером...
echo.

ssh -F "%SSH_CONFIG%" hf "cd /opt/honeyforge && PYTHONIOENCODING=utf-8 python3 - %SVC%" < "%~dp0create-honeypot.py"
set "RC=%ERRORLEVEL%"

echo.
if "%RC%"=="0" (
  echo Готово. Откройте раздел «Ловушки» в панели, чтобы увидеть её.
) else (
  echo Развернуть ловушку не удалось. Код ошибки: %RC%
)
pause
exit /b %RC%
