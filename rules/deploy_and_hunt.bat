@echo off
title Sysmon + Sigma Threat Hunter

:: Install Sysmon if not running
tasklist | findstr /i "sysmon.exe" >nul || (
    sysmon.exe -accepteula -i sysmon_config.xml
)

:: Run Sigma rules
python tools/sigmac -t evtx-attack rules/windows/sysmon/*.yml > sigma_queries.txt

:: Optional: Run Chainsaw with converted rules
:: chainsaw.exe hunt C:\Windows\System32\winevt\Logs --rules sigma_queries.txt --output detection_results.txt

echo Threat hunt complete. Check detection_results.txt
pause