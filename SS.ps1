# discord.gg/ssa 

$global:version = "1.0.0"
$global:isAdmin = $false


function Write-Color {
    param(
        [string]$Text,
        [string]$Color = "White",
        [switch]$NoNewline
    )
    
    $colorMap = @{
        Red = "Red"
        Green = "Green"
        Yellow = "Yellow"
        Blue = "Blue"
        Magenta = "Magenta"
        Cyan = "Cyan"
        White = "White"
        Gray = "Gray"
    }
    
    if ($NoNewline) {
        Write-Host $Text -ForegroundColor $colorMap[$Color] -NoNewline
    }
    else {
        Write-Host $Text -ForegroundColor $colorMap[$Color]
    }
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host "              SCREENSHARE SSA v$global:version" -ForegroundColor Cyan
    Write-Host "                 discord.gg/ssa" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host ""
}


function Invoke-JarParser {
    Write-Color "[*] Iniciando JarParser..." "Yellow"
    
    if ($global:isAdmin) {
        Write-Color "[+] Ya se ejecuta como administrador" "Green"
        try {
            Write-Color "[*] Ejecutando comando..." "Yellow"
            Invoke-RestMethod -Uri 'https://pastebin.com/raw/bRGvrGSw' | Invoke-Expression
            Write-Color "[+] Comando ejecutado exitosamente" "Green"
        }
        catch {
            Write-Color "[!] Error al ejecutar comando: $_" "Red"
        }
    }
    else {
        Write-Color "[*] Solicitando permisos de administrador..." "Yellow"
        
        try {
            $script = "irm 'https://pastebin.com/raw/bRGvrGSw' | iex"
            $bytes = [System.Text.Encoding]::Unicode.GetBytes($script)
            $encodedCommand = [Convert]::ToBase64String($bytes)
            
            Start-Process PowerShell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encodedCommand"
            Write-Color "[+] Solicitud de elevación enviada" "Green"
        }
        catch {
            Write-Color "[!] No se pudo elevar permisos" "Red"
            Write-Color "[*] Ejecuta manualmente como administrador:" "Yellow"
            Write-Host "   powershell -command `"irm 'https://pastebin.com/raw/bRGvrGSw' | iex`"" -ForegroundColor Green
        }
    }
}

function Add-DefenderExclusion {
    param([string]$DownloadPath)
    
    Write-Color "[*] Configurando exclusión de antivirus..." "Cyan"
    Write-Color "[*] Agregando exclusión de Windows Defender para: $DownloadPath" "White" -NoNewline
    
    $success = $false
    
    try {
        if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
            $existingExclusions = (Get-MpPreference -ErrorAction Stop).ExclusionPath
            if ($existingExclusions -notcontains $DownloadPath) {
                Add-MpPreference -ExclusionPath $DownloadPath -ErrorAction Stop
            }
            Write-Color " Éxito" "Green"
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
                Write-Color " Éxito" "Green"
                $success = $true
            }
        }
        catch {
         
        }
    }
    
    if (-not $success) {
        Write-Color " Falló" "Red"
    }
    
    return $success
}

function Download-File {
    param([string]$Url, [string]$FileName, [string]$ToolName, [string]$DownloadPath)
    
    try {
        $outputPath = Join-Path $DownloadPath $FileName
        Write-Color "  Descargando $ToolName" "White" -NoNewline
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $Url -OutFile $outputPath -UserAgent "PowerShell" -UseBasicParsing | Out-Null
        
        if ($FileName -like "*.zip") {
            $extractPath = Join-Path $DownloadPath ($FileName -replace '\.zip$', '')
            Expand-Archive -Path $outputPath -DestinationPath $extractPath -Force | Out-Null
            Remove-Item $outputPath -Force | Out-Null
        }
        Write-Color " Listo" "Green"
        return $true
    }
    catch {
        Write-Color " Falló" "Red"
        return $false
    }
    finally {
        $ProgressPreference = 'Continue'
    }
}

function Download-Tools {
    param([array]$Tools, [string]$CategoryName, [string]$DownloadPath)
    
    $successCount = 0
    
    Write-Color "`n[*] Descargando herramientas $CategoryName" "Cyan"
    foreach ($tool in $Tools) {
        if (Download-File -Url $tool.Url -FileName $tool.File -ToolName $tool.Name -DownloadPath $DownloadPath) {
            $successCount++
        }
    }
    
    Write-Color "[+] $CategoryName`: $successCount/$($Tools.Count) herramientas descargadas exitosamente" "Cyan"
    return $successCount
}

function Invoke-SSADownloadSystem {
    Clear-Host
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "       SISTEMA DE DESCARGAS SSA" -ForegroundColor Cyan
    Write-Host "        discord.gg/ssa" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    Write-Color "[!] ADVERTENCIA: ASEGÚRATE DE TENER EL CONSENTIMIENTO DEL USUARIO ANTES DE EJECUTAR" "Red"
    Write-Color "[!] EL SCRIPT AGREGARÁ C:\SCREENSHARE A LAS EXCLUSIONES DEL ANTIVIRUS" "Red"
    Write-Host ""

    if (-not $global:isAdmin) {
        Write-Color "[!] Esta función requiere privilegios de administrador" "Yellow"
        Write-Color "[*] Solicitando permisos de administrador..." "Yellow"
        
        try {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes('& {irm "https://raw.githubusercontent.com/xsolary1234-hash/Screenshare-Alliance/main/SS.ps1" | iex}')
            $encodedCommand = [Convert]::ToBase64String($bytes)
            
            Start-Process PowerShell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encodedCommand"
            Write-Color "[+] Script reiniciado como administrador" "Green"
            exit
        }
        catch {
            Write-Color "[!] No se pudieron obtener privilegios de administrador" "Red"
            Write-Host ""
            Write-Color "[*] Presiona Enter para continuar..." "White"
            $null = Read-Host
            return
        }
    }
    
    $DownloadPath = "C:\Screenshare"
    if (!(Test-Path $DownloadPath)) {
        New-Item -ItemType Directory -Path $DownloadPath -Force | Out-Null
        Write-Color "[+] Carpeta creada: $DownloadPath" "Green"
    }

    $exclusionAdded = Add-DefenderExclusion -DownloadPath $DownloadPath
    
    if (-not $exclusionAdded) {
        Write-Color "`n[!] No se pudo agregar la exclusión automática del antivirus" "Yellow"
        Write-Color "[*] Continuando con las descargas (algunas podrían ser eliminadas)" "Yellow"
        Start-Sleep -Seconds 2
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
    
    Write-Color "`n[*] Sistema de descargas de herramientas forenses" "Cyan"
    Write-Color "[*] Todas las herramientas se guardarán en: $DownloadPath" "Cyan"
    Write-Host ""
    
    $totalDownloaded = 0
    
    $response = Read-Host "[?] ¿Quieres descargar las herramientas de Spokwn? (S/N)"
    if ($response -match '^[SsYy]') {
        $count = Download-Tools -Tools $spokwnTools -CategoryName "Spokwn" -DownloadPath $DownloadPath
        $totalDownloaded += $count
    }
    
    $response = Read-Host "`n[?] ¿Quieres descargar las herramientas de Orbdiff? (S/N)"
    if ($response -match '^[SsYy]') {
        $count = Download-Tools -Tools $OrbdiffTools -CategoryName "Orbdiff" -DownloadPath $DownloadPath
        $totalDownloaded += $count
    }
    
    $response = Read-Host "`n[?] ¿Quieres descargar las herramientas de Zimmerman? (S/N)"
    if ($response -match '^[SsYy]') {
        $count = Download-Tools -Tools $zimmermanTools -CategoryName "Zimmerman" -DownloadPath $DownloadPath
        
        $runtimeResponse = Read-Host "[?] ¿Quieres instalar el .NET Runtime (requerido para Zimmerman)? (S/N)"
        if ($runtimeResponse -match '^[SsYy]') {
            Download-File -Url "https://builds.dotnet.microsoft.com/dotnet/Sdk/9.0.306/dotnet-sdk-9.0.306-win-x64.exe" -FileName "dotnet-sdk-9.0.306-win-x64.exe" -ToolName ".NET Runtime" -DownloadPath $DownloadPath
            $totalDownloaded++
        }
        $totalDownloaded += $count
    }
    
    $response = Read-Host "`n[?] ¿Quieres descargar las herramientas de Nirsoft? (S/N)"
    if ($response -match '^[SsYy]') {
        $count = Download-Tools -Tools $nirsoftTools -CategoryName "Nirsoft" -DownloadPath $DownloadPath
        $totalDownloaded += $count
    }
    
    Write-Color "`n[!] NOTA: Hayabusa puede ser detectado como virus (es seguro y de código abierto)" "Yellow"
    $response = Read-Host "[?] ¿Quieres descargar Hayabusa? (S/N)"
    if ($response -match '^[SsYy]') {
        if (Download-File -Url "https://github.com/Yamato-Security/hayabusa/releases/download/v3.6.0/hayabusa-3.6.0-win-x64.zip" -FileName "hayabusa-3.6.0-win-x64.zip" -ToolName "Hayabusa" -DownloadPath $DownloadPath) {
            $totalDownloaded++
        }
    }
    
    $response = Read-Host "`n[?] ¿Quieres descargar otras herramientas comunes? (S/N)"
    if ($response -match '^[SsYy]') {
        $count = Download-Tools -Tools $otherTools -CategoryName "Otras herramientas" -DownloadPath $DownloadPath
        $totalDownloaded += $count
    }
    
    Write-Color "`n[+] Descarga completada!" "Green"
    Write-Color "[*] Total de herramientas descargadas: $totalDownloaded" "Cyan"
    
    $response = Read-Host "`n[?] ¿Quieres abrir la carpeta $DownloadPath? (S/N)"
    if ($response -match '^[SsYy]') {
        Start-Process $DownloadPath
    }
    
    Write-Color "`n[*] Las descargas se encuentran en: $DownloadPath" "Cyan"
    Write-Host ""
    Write-Color "[*] Presiona Enter para continuar..." "White"
    $null = Read-Host
}

function Invoke-KillScreenProcesses {
    Clear-Host
    
    Write-Host "======================================================" -ForegroundColor Green
    Write-Host "   Killer Capture Screen Processes made by Diff" -ForegroundColor Green
    Write-Host "======================================================" -ForegroundColor Green
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
        Write-Color "[+] No forbidden or capture processes detected" "Green"
        Write-Host ""
        Write-Color "[*] Presiona Enter para continuar..." "White"
        $null = Read-Host
        return
    }

    Write-Color "[!] Detected processes:" "Yellow"
    Write-Host ""

    foreach ($item in $detected.Values) {
        Write-Host "  - $($item.Name).exe [$($item.Type)]" -ForegroundColor Cyan
    }

    Write-Host ""
    Write-Color "[A] Kill all detected processes" "White"
    Write-Color "[B] Kill 1 specific process" "White"
    Write-Color "[C] Kill all except 1 process" "White"
    Write-Color "[X] Cancelar y volver al menú" "White"
    Write-Host ""

    $choice = Read-Host "[?] Select option (A / B / C / X)"

    switch ($choice.ToUpper()) {
        "A" {
            foreach ($item in $detected.Values) {
                Get-Process -Name $item.Name -ErrorAction SilentlyContinue | Stop-Process -Force
                Write-Host "[Terminated] $($item.Name).exe" -ForegroundColor Red
            }
            Write-Color "[+] All processes terminated" "Green"
        }

        "B" {
            $target = Read-Host "[?] Enter process name (example: chrome or chrome.exe)"
            $target = $target.ToLower().Replace(".exe","")

            if ($detected.ContainsKey($target)) {
                Get-Process -Name $target -ErrorAction SilentlyContinue | Stop-Process -Force
                Write-Host "[Terminated] $target.exe" -ForegroundColor Red
            } else {
                Write-Color "[Error] Process not found" "Red"
            }
        }

        "C" {
            $exclude = Read-Host "[?] Enter process name to keep alive (example: chrome or chrome.exe)"
            $exclude = $exclude.ToLower().Replace(".exe","")

            if (-not $detected.ContainsKey($exclude)) {
                Write-Color "[Error] Process not found" "Red"
                return
            }

            foreach ($key in $detected.Keys) {
                if ($key -ne $exclude) {
                    Get-Process -Name $key -ErrorAction SilentlyContinue | Stop-Process -Force
                    Write-Host "[Terminated] $key.exe" -ForegroundColor Red
                }
            }

            Write-Color "[+] Kept alive: $exclude.exe" "Green"
        }
        
        "X" {
            Write-Color "[*] Cancelado, volviendo al menú principal..." "Yellow"
            return
        }
        
        default {
            Write-Color "[!] Opción no válida" "Red"
        }
    }
    
    Write-Host ""
    Write-Color "[*] Presiona Enter para continuar..." "White"
    $null = Read-Host
}

function Show-Menu {
    Show-Banner
    
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host "                MENÚ PRINCIPAL SSA" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
    
    do {
        Write-Host ""
     
        Write-Color "[1] Ejecutar JarParser" "White"
        Write-Color "[2] Sistema de descargas" "White"
        Write-Color "[3] Kill Screen Processes (by Diff)" "White"
        Write-Color "[4] Salir" "White"
        Write-Host ""
        Write-Host "--------------------------------------------------------" -ForegroundColor Cyan
        
        $choice = Read-Host "[?] Opción (1-4)"
        
        switch ($choice) {
            "1" {
                Write-Host ""
              
                Write-Color "[*] Iniciando JarParser..." "Yellow"
                Write-Color "[!] Esta opción requiere permisos de administrador" "Yellow"
                Write-Host ""
            
                Invoke-JarParser
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
                Write-Host ""
                Write-Color "[+] Saliendo... ¡Hasta pronto!" "Green"
                break
            }
            default {
                Write-Color "[!] Opción no válida" "Red"
                Start-Sleep -Seconds 1
            }
        }
        
        if ($choice -ne "4" -and $choice -ne "2" -and $choice -ne "3") {
            Write-Host ""
            Write-Color "[*] Presiona Enter para continuar..." "White"
            $null = Read-Host
            Show-Banner
        }
    } while ($choice -ne "4")
    
    Write-Host ""
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host "               discord.gg/ssa" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
}

function Main {
    $global:isAdmin = Test-Administrator
    
    try {
        Show-Menu
    }
    catch {
        Write-Color "[!] Error crítico: $_" "Red"
        Write-Host ""
        Read-Host "Presiona Enter para salir..."
    }
}

Main
