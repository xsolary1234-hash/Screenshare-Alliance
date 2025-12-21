
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
    Write-Host "$($colors.Cyan)                                    ███████╗ ██████╗ ██████╗ " -NoNewline
    Write-Host "$($colors.Reset)"
    Write-Host "$($colors.Cyan)                                    ██╔══██╗" -NoNewline
    Write-Host "$($colors.Reset)"
    Write-Host "$($colors.Cyan)                                    ██████╔╝" -NoNewline
    Write-Host "$($colors.Reset)"
    Write-Host "$($colors.Cyan)                                    ██╔══██╗ " -NoNewline
    Write-Host "$($colors.Reset)"
    Write-Host "$($colors.Cyan)                                    ██║  ██║" -NoNewline
    Write-Host "$($colors.Reset)"
    Write-Host "$($colors.Cyan)                                   ╚══════╝███████╗███████╗███╗   ██╗███████╗██╗  ██╗ █████╗ ██████╗ ███████╗" -NoNewline
    Write-Host "$($colors.Reset)"
    Write-Host "$($colors.Cyan)                                    ██╔════╝██╔════╝██╔════╝██╔════╝████╗  ██║██╔════╝██║  ██║██╔══██╗██╔══██╗██╔════╝" -NoNewline
    Write-Host "$($colors.Reset)"
    Write-Host "$($colors.Cyan)                                    ███████╗██║     █████╗  █████╗  ██╔██╗ ██║███████╗███████║███████║██████╔╝█████╗  " -NoNewline
    Write-Host "$($colors.Reset)"
    Write-Host "$($colors.Cyan)                                    ╚════██║██║     ██╔══╝  ██╔══╝  ██║╚██╗██║╚════██║██╔══██║██╔══██║██╔══██╗██╔══╝  " -NoNewline
    Write-Host "$($colors.Reset)"
    Write-Host "$($colors.Cyan)                                    ███████║╚██████╗███████╗███████╗██║ ╚████║███████║██║  ██║██║  ██║██║  ██║███████╗" -NoNewline
    Write-Host "$($colors.Reset)"
    Write-Host "$($colors.Cyan)                                    ╚══════╝ ╚═════╝╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ " -NoNewline
    Write-Host "$($colors.Reset)"
    Write-Host ""
    Write-Host "$($colors.Cyan)                                                        Version: $version" -NoNewline
    Write-Host "$($colors.Reset)"
    Write-Host "$($colors.White)                                        SCREENSHARE Tdiscord.gg/ssa" -NoNewline
    Write-Host "$($colors.Reset)"
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


function Get-NirSoftTools {
    $nirsoftDir = "NirSoft_Tools"
    $tools = @(
        @{Name = "WirelessNetView"; URL = "https://www.nirsoft.net/utils/wirelessnetview.zip"},
        @{Name = "WirelessKeyView"; URL = "https://www.nirsoft.net/utils/wirelesskeyview.zip"},
        @{Name = "CurrPorts"; URL = "https://www.nirsoft.net/utils/cports.zip"},
        @{Name = "ShellExView"; URL = "https://www.nirsoft.net/utils/shexview.zip"},
        @{Name = "FileTypesMan"; URL = "https://www.nirsoft.net/utils/filetypesman.zip"},
        @{Name = "USBDeview"; URL = "https://www.nirsoft.net/utils/usbdeview.zip"},
        @{Name = "WebBrowserPassView"; URL = "https://www.nirsoft.net/utils/webbrowserpassview.zip"},
        @{Name = "ProduKey"; URL = "https://www.nirsoft.net/utils/produkey.zip"},
        @{Name = "BlueScreenView"; URL = "https://www.nirsoft.net/utils/bluescreenview.zip"},
        @{Name = "RegScanner"; URL = "https://www.nirsoft.net/utils/regscanner.zip"}
    )
    
    $downloaded = 0
    $failed = 0
    
    if (-not (Test-Path $nirsoftDir)) {
        New-Item -ItemType Directory -Path $nirsoftDir | Out-Null
    }
    
    foreach ($tool in $tools) {
        try {
            $toolDir = Join-Path $nirsoftDir $tool.Name
            if (-not (Test-Path $toolDir)) {
                New-Item -ItemType Directory -Path $toolDir | Out-Null
            }
            
            Write-Host "$($colors.Yellow)[*] Descargando $($tool.Name)...$($colors.Reset)"
            
            $zipPath = Join-Path $toolDir "$($tool.Name).zip"
            
       
            Invoke-WebRequest -Uri $tool.URL -OutFile $zipPath -UseBasicParsing
            
         
            Expand-Archive -Path $zipPath -DestinationPath $toolDir -Force
            Remove-Item -Path $zipPath -Force
            
            $downloaded++
            Write-Host "$($colors.Green)[+] $($tool.Name) descargado correctamente$($colors.Reset)"
        }
        catch {
            $failed++
            Write-Host "$($colors.Red)[-] Error con $($tool.Name): $_$($colors.Reset)"
        }
    }
    
  
    $readmeContent = @"
# NirSoft Tools Collection
Descargado automáticamente por SCREENSHARE Toolkit

## Herramientas ($downloaded/$($tools.Count)):
$($tools | ForEach-Object { "- $($_.Name)`n" })

## Estadísticas:
- Descargadas: $downloaded
- Fallidas: $failed
- Total: $($tools.Count)

Cada herramienta está en su propia carpeta.
Más en: https://www.nirsoft.net/utils/
"@
    
    Set-Content -Path (Join-Path $nirsoftDir "README.txt") -Value $readmeContent
    
    return @{
        Downloaded = $downloaded
        Failed = $failed
        Directory = $nirsoftDir
    }
}


function Get-EricZimmermanTools {
    $ericDir = "Eric_Zimmerman_Tools"
    $tools = @(
        @{Name = "PECmd"; URL = "https://f001.backblazeb2.com/file/EricZimmermanTools/PECmd.zip"},
        @{Name = "RBCmd"; URL = "https://f001.backblazeb2.com/file/EricZimmermanTools/RBCmd.zip"},
        @{Name = "JLECmd"; URL = "https://f001.backblazeb2.com/file/EricZimmermanTools/JLECmd.zip"},
        @{Name = "EvtxECmd"; URL = "https://f001.backblazeb2.com/file/EricZimmermanTools/EvtxECmd.zip"}
    )
    
    $downloaded = 0
    
    if (-not (Test-Path $ericDir)) {
        New-Item -ItemType Directory -Path $ericDir | Out-Null
    }
    
    foreach ($tool in $tools) {
        try {
            $toolDir = Join-Path $ericDir $tool.Name
            if (-not (Test-Path $toolDir)) {
                New-Item -ItemType Directory -Path $toolDir | Out-Null
            }
            
            Write-Host "$($colors.Yellow)[*] Descargando $($tool.Name)...$($colors.Reset)"
            
            $zipPath = Join-Path $toolDir "$($tool.Name).zip"
            
           
            Invoke-WebRequest -Uri $tool.URL -OutFile $zipPath -UseBasicParsing
            
        
            Expand-Archive -Path $zipPath -DestinationPath $toolDir -Force
            Remove-Item -Path $zipPath -Force
            
            $downloaded++
            Write-Host "$($colors.Green)[+] $($tool.Name) descargado$($colors.Reset)"
        }
        catch {
            Write-Host "$($colors.Red)[-] Error con $($tool.Name): $_$($colors.Reset)"
        }
    }
    
    return @{
        Downloaded = $downloaded
        Directory = $ericDir
    }
}


function Get-AllTools {
    Write-Host "$($colors.Cyan)[*] Iniciando descarga completa de herramientas...$($colors.Reset)"
    
    Write-Host "`n$($colors.Yellow)=== NIRSOFT TOOLS ===$($colors.Reset)"
    $nirsoftResult = Get-NirSoftTools
    
    Write-Host "`n$($colors.Yellow)=== ERIC ZIMMERMAN TOOLS ===$($colors.Reset)"
    $ericResult = Get-EricZimmermanTools
    
    Write-Host "`n$($colors.Green)$('='*50)$($colors.Reset)"
    Write-Host "$($colors.Green)[+] DESCARGA COMPLETADA$($colors.Reset)"
    Write-Host "$($colors.Green)$('='*50)$($colors.Reset)"
    Write-Host "$($colors.White)  • NirSoft: $($nirsoftResult.Downloaded) herramientas en '$($nirsoftResult.Directory)'$($colors.Reset)"
    Write-Host "$($colors.White)  • Eric Zimmerman: $($ericResult.Downloaded) herramientas en '$($ericResult.Directory)'$($colors.Reset)"
    Write-Host "`n$($colors.Cyan)[*] Todas las herramientas se han guardado en sus respectivas carpetas.$($colors.Reset)"
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
    Write-Host "$($colors.Cyan)         SCREENSHARE TOOLKIT - MENÚ PRINCIPAL$($colors.Reset)"
    Write-Host "$($colors.Cyan)$('='*60)$($colors.Reset)"
    
    do {
        Write-Host "`n$($colors.White)Selecciona una opción:$($colors.Reset)"
        Write-Host "$($colors.Cyan)1.$($colors.Reset) Ejecutar Doomsday Fucker (Requiere Admin)"
        Write-Host "$($colors.Cyan)2.$($colors.Reset) Descargar NirSoft Tools"
        Write-Host "$($colors.Cyan)3.$($colors.Reset) Descargar Eric Zimmerman Tools"
        Write-Host "$($colors.Cyan)4.$($colors.Reset) Descargar todas las herramientas"
        Write-Host "$($colors.Cyan)5.$($colors.Reset) Kill Screen Processes (by Diff)"
        Write-Host "$($colors.Cyan)6.$($colors.Reset) Salir"
        Write-Host "$($colors.Cyan)$('-'*60)$($colors.Reset)"
        
        $choice = Read-Host "`n$($colors.Yellow)Opción$($colors.Reset)"
        
        switch ($choice) {
            "1" {
                Write-Host "`n$($colors.Yellow)[*] Iniciando Doomsday Fucker...$($colors.Reset)"
                Write-Host "$($colors.Yellow)[!] Esta opción requiere permisos de administrador$($colors.Reset)"
                Invoke-DoomsdayFucker
            }
            "2" {
                Write-Host "`n$($colors.Yellow)[*] Descargando NirSoft Tools...$($colors.Reset)"
                $result = Get-NirSoftTools
                Write-Host "$($colors.Green)[+] Descargadas: $($result.Downloaded), Fallidas: $($result.Failed)$($colors.Reset)"
                Write-Host "$($colors.Green)[+] Carpeta: $($result.Directory)$($colors.Reset)"
            }
            "3" {
                Write-Host "`n$($colors.Yellow)[*] Descargando Eric Zimmerman Tools...$($colors.Reset)"
                $result = Get-EricZimmermanTools
                Write-Host "$($colors.Green)[+] Descargadas: $($result.Downloaded)$($colors.Reset)"
                Write-Host "$($colors.Green)[+] Carpeta: $($result.Directory)$($colors.Reset)"
            }
            "4" {
                Get-AllTools
            }
            "5" {
                Invoke-KillScreenProcesses
                Show-Banner
                continue
            }
            "6" {
                Write-Host "`n$($colors.Green)[+] Saliendo... ¡Hasta pronto!$($colors.Reset)"
                break
            }
            default {
                Write-Host "$($colors.Red)[!] Opción no válida$($colors.Reset)"
            }
        }
        
        if ($choice -ne "6") {
            Write-Host "`n$($colors.White)Presiona Enter para continuar...$($colors.Reset)"
            $null = Read-Host
            Show-Banner
        }
    } while ($choice -ne "6")
    
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