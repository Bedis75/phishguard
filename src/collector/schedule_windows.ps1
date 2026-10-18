# Crée (ou remplace) la tâche Windows "PhishGuard collecte" : collecte automatique 2 fois par jour.
# Lancement depuis WSL :
#   powershell.exe -ExecutionPolicy Bypass -File "$(wslpath -w src/collector/schedule_windows.ps1)"
# Suppression :
#   powershell.exe -Command "Unregister-ScheduledTask -TaskName 'PhishGuard collecte' -Confirm:`$false"

$taskName = "PhishGuard collecte"
$command  = "wsl.exe -d Ubuntu-24.04 -u bedis -- bash /home/bedis/dev/phishguard/src/collector/auto_collect.sh"

$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -WindowStyle Hidden -Command `"$command`""

# 01:15 et 13:15 heure locale (UTC+1) = 15 min après chaque mise à jour OpenPhish (00:00 et 12:00 UTC)
$triggers = @(
    New-ScheduledTaskTrigger -Daily -At "01:15"
    New-ScheduledTaskTrigger -Daily -At "13:15"
)

$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -WakeToRun `
    -RunOnlyIfNetworkAvailable `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Hours 1) `
    -MultipleInstances IgnoreNew

# Utilisateur courant, seulement quand il est connecté (WSL a besoin de la session ; aucun mot de passe stocké)
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $triggers `
    -Settings $settings -Principal $principal `
    -Description "PhishGuard : collecte OpenPhish + Tranco (src/collector/auto_collect.sh). Journaux : data/live/logs/" `
    -Force | Out-Null

Get-ScheduledTask -TaskName $taskName | Get-ScheduledTaskInfo | Select-Object TaskName, NextRunTime
