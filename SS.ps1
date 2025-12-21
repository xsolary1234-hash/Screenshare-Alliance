# discord.gg/ssa

$global:version = "1.0.0"
$global:isAdmin = $false


$global:colors = @{
    Red = "`e[91m"
    Green = "`e[92m"
    Yellow = "`e[93m"
    Blue = "`e[94m"
    Magenta = "`e[95m"
    Cyan = "`e[96m"
    White = "`e[97m"
    Reset = "`e[0m"
}


function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}


function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "$($colors.Cyan)╔══════════════════════════════════════════════════════════╗$($colors.Reset)"
    Write-Host "$($colors.Cyan)║                                                          ║$($colors.Reset)"
    Write-Host "$($colors.Cyan)║$($colors.White)  Screenshare SSA v$version$($colors.Cyan)                      ║$($colors.Reset)"
    Write-Host "$($colors.Cyan)║$($colors.White)       discord.gg/ssa      $($colors.Cyan)                     ║$($colors.Reset)"
    Write-Host "$($colors.Cyan)║                                                          ║$($colors.Reset)"
    Write-Host "$($colors.Cyan)╚══════════════════════════════════════════════════════════╝$($colors.Reset)"
    Write-Host ""
}


function Invoke-DoomsdayFucker {
    Write-Host "$($colors.Yellow)[*] Iniciando Doomsday Fucker...$($colors.Reset)"
    
    if ($global:isAdmin) {
        Write-Host "$($colors.Green)[+] Ya se ejecuta como administrador$($colors.Reset)"
        try {
            Write-Host "$($colors.Yellow)[*] Ejecutando comando...$($colors.Reset)"
            Invoke-RestMethod -Uri 'https://pastebin.com/raw/bRGvrGSw' | Invoke-Expression
            Write-Host "$($colors.Green)[+] Comando ejecutado exitosamente$($colors.Reset)"
        }
        catch {
            Write-Host "$($colors.Red)[!] Error al ejecutar comando: $_$($colors.Reset)"
        }
    }
    else {
        Write-Host "$($colors.Yellow)[*] Solicitando permisos de administrador...$($colors.Reset)"
        
        try {
          
            $script = "irm 'https://pastebin.com/raw/bRGvrGSw' | iex"
            $bytes = [System.Text.Encoding]::Unicode.GetBytes($script)
            $encodedCommand = [Convert]::ToBase64String($bytes)
            
            Start-Process PowerShell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encodedCommand"
            Write-Host "$($colors.Green)[+] Solicitud de elevación enviada$($colors.Reset)"
        }
        catch {
            Write-Host "$($colors.Red)[!] No se pudo elevar permisos$($colors.Reset)"
            Write-Host "$($colors.Yellow)[*] Ejecuta manualmente como administrador:$($colors.Reset)"
            Write-Host "$($colors.Green)   powershell -command `"irm 'https://pastebin.com/raw/bRGvrGSw' | iex`"$($colors.Reset)"
        }
    }
}


function Add-DefenderExclusion {
    param([string]$DownloadPath)
    
    Write-Host "$($colors.Cyan)[*] Configurando exclusión de antivirus...$($colors.Reset)"
    Write-Host "$($colors.White)[*] Agregando exclusión de Windows Defender para: $DownloadPath" -NoNewline
    
    $success = $false
    
    try {
        if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
            $existingExclusions = (Get-MpPreference -ErrorAction Stop).ExclusionPath
            if ($existingExclusions -notcontains $DownloadPath) {
                Add-MpPreference -ExclusionPath $DownloadPath -ErrorAction Stop
            }
            Write-Host "$($colors.Green) Éxito$($colors.Reset)"
            $success = $true
        }
    }
    catch {
     
    }
    
    if (-not $success) {
        try {
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
            if (Test-Path $regPath) {
                $existingValue = Get-ItemProperty -Path $regPath -Name $DownloadPath -ErrorAction SilentlyContinue
                if (-not $existingValue) {
                    New-ItemProperty -Path $regPath -Name $DownloadPath -Value 0 -PropertyType DWORD -Force -ErrorAction Stop | Out-Null
                }
                Write-Host "$($colors.Green) Éxito$($colors.Reset)"
                $success = $true
            }
        }
        catch {
         
        }
    }
    
    if (-not $success) {
        Write-Host "$($colors.Red) Falló$($colors.Reset)"
    }
    
    return $success
}


function Download-File {
    param([string]$Url, [string]$FileName, [string]$ToolName, [string]$DownloadPath)
    
    try {
        $outputPath = Join-Path $DownloadPath $FileName
        Write-Host "$($colors.White)  Descargando $ToolName" -NoNewline
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $Url -OutFile $outputPath -UserAgent "PowerShell" -UseBasicParsing | Out-Null
        
        if ($FileName -like "*.zip") {
            $extractPath = Join-Path $DownloadPath ($FileName -replace '\.zip$', '')
            Expand-Archive -Path $outputPath -DestinationPath $extractPath -Force | Out-Null
            Remove-Item $outputPath -Force | Out-Null
        }
        Write-Host "$($colors.Green) Listo$($colors.Reset)"
        return $true
    }
    catch {
        Write-Host "$($colors.Red) Falló$($colors.Reset)"
        return $false
    }
    finally {
        $ProgressPreference = 'Continue'
    }
}


function Download-Tools {
    param([array]$Tools, [string]$CategoryName, [string]$DownloadPath)
    
    $successCount = 0
    
    Write-Host "`n$($colors.Cyan)[*] Descargando herramientas $CategoryName$($colors.Reset)"
    foreach ($tool in $Tools) {
        if (Download-File -Url $tool.Url -FileName $tool.File -ToolName $tool.Name -DownloadPath $DownloadPath) {
            $successCount++
        }
    }
    

    Write-Host ("$($colors.Cyan)[+] {0}: {1}/{2} herramientas descargadas exitosamente$($colors.Reset)" -f $CategoryName, $successCount, $Tools.Count)
    return $successCount
}


function Invoke-SSADownloadSystem {
    Clear-Host
    
    Write-Host @"
$($colors.Cyan)   
Discord.gg/ssa
$($colors.Reset)
$($colors.White)discord.gg/ssa$($colors.Reset)
"@

    Write-Host "`n$($colors.Red)[!] ADVERTENCIA: ASEGÚRATE DE TENER EL CONSENTIMIENTO DEL USUARIO ANTES DE EJECUTAR,$($colors.Reset)"
    Write-Host "$($colors.Red)[!] EL SCRIPT AGREGARÁ C:\SCREENSHARE A LAS EXCLUSIONES DEL ANTIVIRUS.$($colors.Reset)"
    Write-Host ""
    

    if (-not $global:isAdmin) {
        Write-Host "$($colors.Yellow)[!] Esta función requiere privilegios de administrador.$($colors.Reset)"
        Write-Host "$($colors.Yellow)[*] Solicitando permisos de administrador...$($colors.Reset)"
        
        try {
            $scriptContent = Get-Content $MyInvocation.MyCommand.Path -Raw
            $bytes = [System.Text.Encoding]::Unicode.GetBytes($scriptContent)
            $encodedCommand = [Convert]::ToBase64String($bytes)
            
            Start-Process PowerShell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encodedCommand"
            Write-Host "$($colors.Green)[+] Script reiniciado como administrador$($colors.Reset)"
            exit
        }
        catch {
            Write-Host "$($colors.Red)[!] No se pudieron obtener privilegios de administrador.$($colors.Reset)"
            Write-Host "$($colors.White)[*] Presiona Enter para continuar...$($colors.Reset)"
            $null = Read-Host
            return
        }
    }
    
    $DownloadPath = "C:\Screenshare"
    if (!(Test-Path $DownloadPath)) {
        New-Item -ItemType Directory -Path $DownloadPath -Force | Out-Null
        Write-Host "$($colors.Green)[+] Carpeta creada: $DownloadPath$($colors.Reset)"
    }
    

    $exclusionAdded = Add-DefenderExclusion -DownloadPath $DownloadPath
    
    if (-not $exclusionAdded) {
        Write-Host "`n$($colors.Yellow)[!] No se pudo agregar la exclusión automática del antivirus.$($colors.Reset)"
        Write-Host "$($colors.Yellow)[*] Continuando con las descargas (algunas podrían ser eliminadas)$($colors.Reset)"
        Start-Sleep -Seconds 3
    }
    

    $spokwnTools = @(
        @{ Name="Kernel Live Dump Analyzer Parser"; Url="https://github.com/spokwn/KernelLiveDumpTool/releases/download/v1.1/KernelLiveDumpTool.exe"; File="KernelLiveDumpTool.exe" },
        @{ Name="BAM Parser"; Url="https://github.com/spokwn/BAM-parser/releases/download/v1.2.9/BAMParser.exe"; File="BAMParser.exe" },
        @{ Name="Paths Parser"; Url="https://github.com/spokwn/PathsParser/releases/download/v1.2/PathsParser.exe"; File="PathsParser.exe" },
        @{ Name="JournalTrace"; Url="https://github.com/spokwn/JournalTrace/releases/download/1.2/JournalTrace.exe"; File="JournalTrace.exe" },
        @{ Name="Tool"; Url="https://github.com/spokwn/Tool/releases/download/v1.1.3/espouken.exe"; File="espouken.exe" },
        @{ Name="PcaSvc Executed"; Url="https://github.com/spokwn/pcasvc-executed/releases/download/v0.8.7/PcaSvcExecuted.exe"; File="PcaSvcExecuted.exe" },
        @{ Name="BAM Deleted Keys"; Url="https://github.com/spokwn/BamDeletedKeys/releases/download/v1.0/BamDeletedKeys.exe"; File="BamDeletedKeys.exe" },
        @{ Name="Prefetch Parser"; Url="https://github.com/spokwn/prefetch-parser/releases/download/v1.5.5/PrefetchParser.exe"; File="PrefetchParser.exe" },
        @{ Name="Activities Cache Parser"; Url="https://github.com/spokwn/ActivitiesCache-execution/releases/download/v0.6.5/ActivitiesCacheParser.exe"; File="ActivitiesCacheParser.exe" }
    )

    $zimmermanTools = @(
        @{ Name="AmcacheParser"; Url="https://download.ericzimmermanstools.com/net9/AmcacheParser.zip"; File="AmcacheParser.zip" },
        @{ Name="AppCompatCacheParser"; Url="https://download.ericzimmermanstools.com/net9/AppCompatCacheParser.zip"; File="AppCompatCacheParser.zip" },
        @{ Name="JumpListExplorer"; Url="https://download.ericzimmermanstools.com/net9/JumpListExplorer.zip"; File="JumpListExplorer.zip" },
        @{ Name="bstrings"; Url="https://download.ericzimmermanstools.com/net9/bstrings.zip"; File="bstrings.zip" },
        @{ Name="PECmd"; Url="https://download.ericzimmermanstools.com/net9/PECmd.zip"; File="PECmd.zip" },
        @{ Name="SrumECmd"; Url="https://download.ericzimmermanstools.com/net9/SrumECmd.zip"; File="SrumECmd.zip" },
        @{ Name="TimelineExplorer"; Url="https://download.ericzimmermanstools.com/net9/TimelineExplorer.zip"; File="TimelineExplorer.zip" },
        @{ Name="RegistryExplorer"; Url="https://download.ericzimmermanstools.com/net9/RegistryExplorer.zip"; File="RegistryExplorer.zip" },
        @{ Name="MFTECmd"; Url="https://download.ericzimmermanstools.com/net9/MFTECmd.zip"; File="MFTECmd.zip"}
    )

    $nirsoftTools = @(
        @{ Name="WinPrefetchView"; Url="https://www.nirsoft.net/utils/winprefetchview-x64.zip"; File="winprefetchview-x64.zip" },
        @{ Name="USBDeview"; Url="https://www.nirsoft.net/utils/usbdeview-x64.zip"; File="usbdeview-x64.zip" },
        @{ Name="NetworkUsageView"; Url="https://www.nirsoft.net/utils/networkusageview-x64.zip"; File="networkusageview-x64.zip" },
        @{ Name="AlternateStreamView"; Url="https://www.nirsoft.net/utils/alternatestreamview-x64.zip"; File="alternatestreamview-x64.zip" },
        @{ Name="UninstallView"; Url="https://www.nirsoft.net/utils/uninstallview-x64.zip"; File="uninstallview-x64.zip" },
        @{ Name="PreviousFilesRecovery"; Url="https://www.nirsoft.net/utils/previousfilesrecovery-x64.zip"; File="previousfilesrecovery-x64.zip" }
    )

    $OrbdiffTools = @(
        @{ Name="Fileless"; Url="https://github.com/Orbdiff/Fileless/releases/download/v1.1/Fileless.exe"; File="Fileless.exe" },
        @{ Name="JARParser"; Url="https://github.com/Orbdiff/JARParser/releases/download/v1.2/JARParser.exe"; File="JARParser.exe" },
        @{ Name="PFTrace"; Url="https://github.com/Orbdiff/PFTrace/releases/download/v1.0.1/PFTrace.exe"; File="PFTrace.exe" },
        @{ Name="Prefetchview++"; Url="https://github.com/Orbdiff/PrefetchView/releases/download/v1.4/PrefetchView++.exe"; File="PrefetchView++.exe" }
    )

    $otherTools = @(
        @{ Name="System Informer"; Url="https://github.com/winsiderss/si-builds/releases/download/3.2.25297.1516/systeminformer-build-canary-setup.exe"; File="systeminformer-build-canary-setup.exe" },
        @{ Name="Everything Search"; Url="https://www.voidtools.com/Everything-1.4.1.1029.x86-Setup.exe"; File="Everything-1.4.1.1029.x86-Setup.exe" },
        @{ Name="FTK Imager"; Url="https://d1kpmuwb7gvu1i.cloudfront.net/AccessData_FTK_Imager_4.7.1.exe"; File="AccessData_FTK_Imager_4.7.1.exe" }
    )
    

    Write-Host "`n$($colors.Cyan)[*] Sistema de descargas de herramientas forenses$($colors.Reset)"
    Write-Host "$($colors.Cyan)[*] Todas las herramientas se guardarán en: $DownloadPath$($colors.Reset)"
    Write-Host ""
    
    $totalDownloaded = 0
    
    $response = Read-Host "$($colors.Yellow)[?] ¿Quieres descargar las herramientas de Spokwn? (S/N)$($colors.Reset)"
    if ($response -match '^[SsYy]') {
        $count = Download-Tools -Tools $spokwnTools -CategoryName "Spokwn" -DownloadPath $DownloadPath
        $totalDownloaded += $count
    }
    
    $response = Read-Host "`n$($colors.Yellow)[?] ¿Quieres descargar las herramientas de Orbdiff? (S/N)$($colors.Reset)"
    if ($response -match '^[SsYy]') {
        $count = Download-Tools -Tools $OrbdiffTools -CategoryName "Orbdiff" -DownloadPath $DownloadPath
        $totalDownloaded += $count
    }
    
    $response = Read-Host "`n$($colors.Yellow)[?] ¿Quieres descargar las herramientas de Zimmerman? (S/N)$($colors.Reset)"
    if ($response -match '^[SsYy]') {
        $count = Download-Tools -Tools $zimmermanTools -CategoryName "Zimmerman" -DownloadPath $DownloadPath
        
        $runtimeResponse = Read-Host "$($colors.Yellow)[?] ¿Quieres instalar el .NET Runtime (requerido para Zimmerman)? (S/N)$($colors.Reset)"
        if ($runtimeResponse -match '^[SsYy]') {
            Download-File -Url "https://builds.dotnet.microsoft.com/dotnet/Sdk/9.0.306/dotnet-sdk-9.0.306-win-x64.exe" -FileName "dotnet-sdk-9.0.306-win-x64.exe" -ToolName ".NET Runtime" -DownloadPath $DownloadPath
            $totalDownloaded++
        }
        $totalDownloaded += $count
    }
    
    $response = Read-Host "`n$($colors.Yellow)[?] ¿Quieres descargar las herramientas de Nirsoft? (S/N)$($colors.Reset)"
    if ($response -match '^[SsYy]') {
        $count = Download-Tools -Tools $nirsoftTools -CategoryName "Nirsoft" -DownloadPath $DownloadPath
        $totalDownloaded += $count
    }
    
    Write-Host "`n$($colors.Yellow)[!] NOTA: Hayabusa puede ser detectado como virus (es seguro y de código abierto)$($colors.Reset)"
    $response = Read-Host "$($colors.Yellow)[?] ¿Quieres descargar Hayabusa? (S/N)$($colors.Reset)"
    if ($response -match '^[SsYy]') {
        if (Download-File -Url "https://github.com/Yamato-Security/hayabusa/releases/download/v3.6.0/hayabusa-3.6.0-win-x64.zip" -FileName "hayabusa-3.6.0-win-x64.zip" -ToolName "Hayabusa" -DownloadPath $DownloadPath) {
            $totalDownloaded++
        }
    }
    
    $response = Read-Host "`n$($colors.Yellow)[?] ¿Quieres descargar otras herramientas comunes? (S/N)$($colors.Reset)"
    if ($response -match '^[SsYy]') {
        $count = Download-Tools -Tools $otherTools -CategoryName "Otras herramientas" -DownloadPath $DownloadPath
        $totalDownloaded += $count
    }
    
    Write-Host "`n$($colors.Green)[+] Descarga completada!$($colors.Reset)"
    Write-Host "$($colors.Cyan)[*] Total de herramientas descargadas: $totalDownloaded$($colors.Reset)"
    
    $response = Read-Host "`n$($colors.Yellow)[?] ¿Quieres abrir la carpeta $DownloadPath? (S/N)$($colors.Reset)"
    if ($response -match '^[SsYy]') {
        Start-Process $DownloadPath
    }
    
    Write-Host "`n$($colors.Cyan)[*] Las descargas se encuentran en: $DownloadPath$($colors.Reset)"
    Write-Host "$($colors.White)[*] Presiona Enter para continuar...$($colors.Reset)"
    $null = Read-Host
}

# Función Kill Screen Processes (Script by diff)
function Invoke-KillScreenProcesses {
    Clear-Host
    
    Write-Host "$($colors.Green)======================================================$($colors.Reset)"
    Write-Host "$($colors.Green)   Killer Capture Screen Processes made by Diff$($colors.Reset)"
    Write-Host "$($colors.Green)======================================================$($colors.Reset)"
    Write-Host ""
    
    $forbiddenProcesses = @(
        "chrome","firefox","msedge","opera","opera_gx","brave","vivaldi",
        "browser","waterfox","librewolf","palemoon","tor","torbrowser",
        "chromium","ungoogled-chromium","epicbrowser","slimjet","comodo",

        "obs","obs32","obs64","streamlabs","camtasia","bandicam","xsplit",
        "fraps","action","dxtory","sharex","screenrec","flashback",

        "gamebar","xboxgamebar","gamebarpresencewriter","broadcastdvr",
        "discord","discordcanary","discordptb","steam","steamwebhelper",
        "overwolf","teams","riotclientservices","epicgameslauncher",

        "nvcontainer","nvdisplay.container","nvidiashare","nvbackend",
        "nvsphelper64","nvstreamer","nvtray","nvtelemetry","nvfbc","nvifrex",

        "amdsoftware","radeonsoftware","amdxcapture","amdenc","amddvr"
    )

    $detected = @{}
    $allProcs = Get-Process -ErrorAction SilentlyContinue

    foreach ($proc in $allProcs) {
        try {
            $name = $proc.Name.ToLower()
            $isForbidden = $forbiddenProcesses -contains $name
            $isCapture = $false

            $modules = $proc.Modules.ModuleName
            if (
                $modules -contains "Windows.Graphics.Capture.dll" -or
                $modules -match "graphicscapture" -or
                $modules -match "nvencodeapi" -or
                $modules -match "amdenc|amf"
            ) {
                $isCapture = $true
            }

            if (($isForbidden -or $isCapture) -and -not $detected.ContainsKey($name)) {
                $detected[$name] = @{
                    Name = $proc.Name
                    Type = if ($isForbidden -and $isCapture) {
                        "Capture + Forbidden"
                    } elseif ($isCapture) {
                        "Screen Capture"
                    } else {
                        "Forbidden Process"
                    }
                }
            }
        } catch {}
    }

    if ($detected.Count -eq 0) {
        Write-Host "$($colors.Green)[+] No forbidden or capture processes detected.$($colors.Reset)"
        Write-Host "`n$($colors.White)Presiona Enter para continuar...$($colors.Reset)"
        $null = Read-Host
        return
    }

    Write-Host "$($colors.Yellow)[!] Detected processes:$($colors.Reset)"
    Write-Host ""

    foreach ($item in $detected.Values) {
        Write-Host "$($colors.Cyan)  - $($item.Name).exe [$($item.Type)]$($colors.Reset)"
    }

    Write-Host ""
    Write-Host "$($colors.White)[A] Kill all detected processes.$($colors.Reset)"
    Write-Host "$($colors.White)[B] Kill 1 specific process.$($colors.Reset)"
    Write-Host "$($colors.White)[C] Kill all except 1 process.$($colors.Reset)"
    Write-Host "$($colors.White)[X] Cancelar y volver al menú.$($colors.Reset)"
    Write-Host ""

    $choice = Read-Host "$($colors.Yellow)Select option (A / B / C / X)$($colors.Reset)"

    switch ($choice.ToUpper()) {
        "A" {
            foreach ($item in $detected.Values) {
                Get-Process -Name $item.Name -ErrorAction SilentlyContinue |
                    Stop-Process -Force
                Write-Host "$($colors.Red)[Terminated] $($item.Name).exe$($colors.Reset)"
            }
            Write-Host "$($colors.Green)[+] All processes terminated.$($colors.Reset)"
        }

        "B" {
            $target = Read-Host "$($colors.Yellow)Enter process name (example: chrome or chrome.exe)$($colors.Reset)"
            $target = $target.ToLower().Replace(".exe","")

            if ($detected.ContainsKey($target)) {
                Get-Process -Name $target -ErrorAction SilentlyContinue |
                    Stop-Process -Force
                Write-Host "$($colors.Red)[Terminated] $target.exe$($colors.Reset)"
            } else {
                Write-Host "$($colors.Red)[Error] Process not found.$($colors.Reset)"
            }
        }

        "C" {
            $exclude = Read-Host "$($colors.Yellow)Enter process name to keep alive (example: chrome or chrome.exe)$($colors.Reset)"
            $exclude = $exclude.ToLower().Replace(".exe","")

            if (-not $detected.ContainsKey($exclude)) {
                Write-Host "$($colors.Red)[Error] Process not found.$($colors.Reset)"
                return
            }

            foreach ($key in $detected.Keys) {
                if ($key -ne $exclude) {
                    Get-Process -Name $key -ErrorAction SilentlyContinue |
                        Stop-Process -Force
                    Write-Host "$($colors.Red)[Terminated] $key.exe$($colors.Reset)"
                }
            }

            Write-Host "$($colors.Green)[+] Kept alive: $exclude.exe$($colors.Reset)"
        }
        
        "X" {
            Write-Host "$($colors.Yellow)[*] Cancelado, volviendo al menú principal...$($colors.Reset)"
            return
        }
        
        default {
            Write-Host "$($colors.Red)[!] Opción no válida$($colors.Reset)"
        }
    }
    
    Write-Host "`n$($colors.White)Presiona Enter para continuar...$($colors.Reset)"
    $null = Read-Host
}


function Show-Menu {
    Show-Banner
    
    Write-Host "`n$($colors.Cyan)$('='*60)$($colors.Reset)"
    Write-Host "$($colors.Cyan)         SCREENSHARE - MENÚ PRINCIPAL$($colors.Reset)"
    Write-Host "$($colors.Cyan)$('='*60)$($colors.Reset)"
    
    do {
        Write-Host "`n$($colors.White)Selecciona una opción:$($colors.Reset)"
        Write-Host "$($colors.Cyan)1.$($colors.Reset) Ejecutar Doomsday Fucker"
        Write-Host "$($colors.Cyan)2.$($colors.Reset) Sistema de descargas"
        Write-Host "$($colors.Cyan)3.$($colors.Reset) Kill Screen Processes (by Diff)"
        Write-Host "$($colors.Cyan)4.$($colors.Reset) Salir"
        Write-Host "$($colors.Cyan)$('-'*60)$($colors.Reset)"
        
        $choice = Read-Host "`n$($colors.Yellow)Opción$($colors.Reset)"
        
        switch ($choice) {
            "1" {
                Write-Host "`n$($colors.Yellow)[*] Iniciando Doomsday Fucker...$($colors.Reset)"
                Write-Host "$($colors.Yellow)[!] Esta opción requiere permisos de administrador$($colors.Reset)"
                Invoke-DoomsdayFucker
            }
            "2" {
                Invoke-SSADownloadSystem
                Show-Banner
                continue
            }
            "3" {
                Invoke-KillScreenProcesses
                Show-Banner
                continue
            }
            "4" {
                Write-Host "`n$($colors.Green)[+] Saliendo... ¡Hasta pronto!$($colors.Reset)"
                break
            }
            default {
                Write-Host "$($colors.Red)[!] Opción no válida$($colors.Reset)"
            }
        }
        
        if ($choice -ne "4" -and $choice -ne "2" -and $choice -ne "3") {
            Write-Host "`n$($colors.White)Presiona Enter para continuar...$($colors.Reset)"
            $null = Read-Host
            Show-Banner
        }
    } while ($choice -ne "4")
    
    Write-Host "`n$($colors.Cyan)$('='*60)$($colors.Reset)"
    Write-Host "$($colors.Cyan)               discord.gg/ssa$($colors.Reset)"
    Write-Host "$($colors.Cyan)$('='*60)$($colors.Reset)"
}


function Main {

    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    
 
    $global:isAdmin = Test-Administrator
    
    try {
        Show-Menu
    }
    catch {
        Write-Host "$($colors.Red)[!] Error crítico: $_$($colors.Reset)"
        Read-Host "Presiona Enter para salir..."
    }
}


Main
