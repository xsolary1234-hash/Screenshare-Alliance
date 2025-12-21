# discord.gg/ssa 

$global:version = "2.0.0"
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
    Write-Host "               SCREENSHARE SSA    v$global:version" -ForegroundColor Cyan
    Write-Host "                discord.gg/ssa" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host ""
}


function Show-PrefetchMenu {
    Clear-Host
    
    Write-Host ""
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host "                   PREFETCH MENÚ " -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Color "[1] PrefetchView++ (Orbdiff)" "White"
    Write-Color "[2] WinPrefetchView (Nirsoft)" "White"
    Write-Color "[3] Prefetch Parser (Spokwn)" "White"
    Write-Color "[4] Analizar prefetch local" "White"
    Write-Color "[5] Volver al menú principal" "White"
    Write-Host ""
    Write-Host "--------------------------------------------------------" -ForegroundColor Gray
    
    $choice = Read-Host "[?] Selecciona opción (1-5)"
    
    switch ($choice) {
        "1" {
            Write-Host ""
            Write-Color "[*] Descargando PrefetchView++ de Orbdiff..." "Yellow"
            
            $downloadPath = "C:\Screenshare\PrefetchTools"
            if (!(Test-Path $downloadPath)) {
                New-Item -ItemType Directory -Path $downloadPath -Force | Out-Null
            }
            
            try {
                $url = "https://github.com/Orbdiff/PrefetchView/releases/download/v1.4/PrefetchView++.exe"
                $outputFile = "$downloadPath\PrefetchView++.exe"
                
                Write-Color "  Descargando..." "White" -NoNewline
                Invoke-WebRequest -Uri $url -OutFile $outputFile -UseBasicParsing | Out-Null
                Write-Color " OK" "Green"
                
                Write-Color "[+] Herramienta descargada en: $downloadPath" "Green"
                
                $open = Read-Host "`n[?] ¿Abrir carpeta? (S/N)"
                if ($open -match '^[SsYy]') {
                    Start-Process $downloadPath
                }
            }
            catch {
                Write-Color "[!] Error al descargar: $_" "Red"
            }
        }
        "2" {
            Write-Host ""
            Write-Color "[*] Descargando WinPrefetchView de Nirsoft..." "Yellow"
            
            $downloadPath = "C:\Screenshare\PrefetchTools"
            if (!(Test-Path $downloadPath)) {
                New-Item -ItemType Directory -Path $downloadPath -Force | Out-Null
            }
            
            try {
                $url = "https://www.nirsoft.net/utils/winprefetchview-x64.zip"
                $outputFile = "$downloadPath\winprefetchview-x64.zip"
                
                Write-Color "  Descargando..." "White" -NoNewline
                Invoke-WebRequest -Uri $url -OutFile $outputFile -UseBasicParsing | Out-Null
                
        
                Expand-Archive -Path $outputFile -DestinationPath $downloadPath -Force | Out-Null
                Remove-Item $outputFile -Force | Out-Null
                
                Write-Color " OK" "Green"
                Write-Color "[+] Herramienta descargada y extraída en: $downloadPath" "Green"
                
                $open = Read-Host "`n[?] ¿Abrir carpeta? (S/N)"
                if ($open -match '^[SsYy]') {
                    Start-Process $downloadPath
                }
            }
            catch {
                Write-Color "[!] Error al descargar: $_" "Red"
            }
        }
        "3" {
            Write-Host ""
            Write-Color "[*] Descargando Prefetch Parser de Spokwn..." "Yellow"
            
            $downloadPath = "C:\Screenshare\PrefetchTools"
            if (!(Test-Path $downloadPath)) {
                New-Item -ItemType Directory -Path $downloadPath -Force | Out-Null
            }
            
            try {
                $url = "https://github.com/spokwn/prefetch-parser/releases/download/v1.5.5/PrefetchParser.exe"
                $outputFile = "$downloadPath\PrefetchParser.exe"
                
                Write-Color "  Descargando..." "White" -NoNewline
                Invoke-WebRequest -Uri $url -OutFile $outputFile -UseBasicParsing | Out-Null
                Write-Color " OK" "Green"
                
                Write-Color "[+] Herramienta descargada en: $downloadPath" "Green"
                
                $open = Read-Host "`n[?] ¿Abrir carpeta? (S/N)"
                if ($open -match '^[SsYy]') {
                    Start-Process $downloadPath
                }
            }
            catch {
                Write-Color "[!] Error al descargar: $_" "Red"
            }
        }
        "4" {
            Write-Host ""
            Write-Color "[*] Analizando archivos Prefetch locales..." "Yellow"
            
            $prefetchPath = "$env:SystemRoot\Prefetch"
            if (Test-Path $prefetchPath) {
                $prefetchFiles = Get-ChildItem -Path $prefetchPath -Filter "*.pf" | Select-Object -First 10
                
                if ($prefetchFiles.Count -gt 0) {
                    Write-Color "[+] Se encontraron $($prefetchFiles.Count) archivos .pf" "Green"
                    Write-Host ""
                    Write-Color "Últimos archivos Prefetch:" "Cyan"
                    
                    foreach ($file in $prefetchFiles) {
                        Write-Host "  - $($file.Name) ($([math]::Round($file.Length/1KB, 2)) KB)" -ForegroundColor White
                    }
                }
                else {
                    Write-Color "[!] No se encontraron archivos .pf" "Yellow"
                }
            }
            else {
                Write-Color "[!] No se encontró la carpeta Prefetch" "Red"
            }
        }
        "5" {
            return
        }
        default {
            Write-Color "[!] Opción no válida" "Red"
            Start-Sleep -Seconds 1
        }
    }
    
    Write-Host ""
    Write-Color "[*] Presiona Enter para continuar..." "White"
    $null = Read-Host
    Show-PrefetchMenu
}


function Show-AnalyzersMenu {
    Clear-Host
    
    Write-Host ""
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host "                MENÚ ANALIZADORES" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Color "[1] Herramientas de Spokwn" "White"
    Write-Color "[2] Herramientas de Zimmerman" "White"
    Write-Color "[3] Herramientas de Nirsoft" "White"
    Write-Color "[4] Herramientas de Orbdiff" "White"
    Write-Color "[5] Volver al menú principal" "White"
    Write-Host ""
    Write-Host "--------------------------------------------------------" -ForegroundColor Gray
    
    $choice = Read-Host "[?] Selecciona opción (1-5)"
    
    switch ($choice) {
        "1" {
            Invoke-SpokwnTools
        }
        "2" {
            Invoke-ZimmermanTools
        }
        "3" {
            Invoke-NirsoftTools
        }
        "4" {
            Invoke-OrbdiffTools
        }
        "5" {
            return
        }
        default {
            Write-Color "[!] Opción no válida" "Red"
            Start-Sleep -Seconds 1
            Show-AnalyzersMenu
        }
    }
}

function Invoke-SpokwnTools {
    Clear-Host
    Write-Host ""
    Write-Color "[*] Descargando herramientas de Spokwn..." "Yellow"
    
    $downloadPath = "C:\Screenshare\SpokwnTools"
    if (!(Test-Path $downloadPath)) {
        New-Item -ItemType Directory -Path $downloadPath -Force | Out-Null
    }
    
    $tools = @(
        @{Name="Kernel Live Dump Analyzer"; Url="https://github.com/spokwn/KernelLiveDumpTool/releases/download/v1.1/KernelLiveDumpTool.exe"},
        @{Name="BAM Parser"; Url="https://github.com/spokwn/BAM-parser/releases/download/v1.2.9/BAMParser.exe"},
        @{Name="Paths Parser"; Url="https://github.com/spokwn/PathsParser/releases/download/v1.2/PathsParser.exe"},
        @{Name="JournalTrace"; Url="https://github.com/spokwn/JournalTrace/releases/download/1.2/JournalTrace.exe"}
    )
    
    $success = 0
    foreach ($tool in $tools) {
        Write-Color "  $($tool.Name)..." "White" -NoNewline
        try {
            $outputFile = "$downloadPath\$($tool.Name).exe"
            Invoke-WebRequest -Uri $tool.Url -OutFile $outputFile -UseBasicParsing | Out-Null
            Write-Color " OK" "Green"
            $success++
        }
        catch {
            Write-Color " ERROR" "Red"
        }
    }
    
    Write-Color "`n[+] $success/$($tools.Count) herramientas descargadas" "Green"
    Write-Color "[*] Ruta: $downloadPath" "Cyan"
    
    Write-Host ""
    Write-Color "[*] Presiona Enter para continuar..." "White"
    $null = Read-Host
    Show-AnalyzersMenu
}

function Invoke-ZimmermanTools {
    Clear-Host
    Write-Host ""
    Write-Color "[*] Descargando herramientas de Zimmerman..." "Yellow"
    
    $downloadPath = "C:\Screenshare\ZimmermanTools"
    if (!(Test-Path $downloadPath)) {
        New-Item -ItemType Directory -Path $downloadPath -Force | Out-Null
    }
    
    $tools = @(
        @{Name="AmcacheParser"; Url="https://download.ericzimmermanstools.com/net9/AmcacheParser.zip"},
        @{Name="AppCompatCacheParser"; Url="https://download.ericzimmermanstools.com/net9/AppCompatCacheParser.zip"},
        @{Name="RegistryExplorer"; Url="https://download.ericzimmermanstools.com/net9/RegistryExplorer.zip"}
    )
    
    $success = 0
    foreach ($tool in $tools) {
        Write-Color "  $($tool.Name)..." "White" -NoNewline
        try {
            $outputFile = "$downloadPath\$($tool.Name).zip"
            Invoke-WebRequest -Uri $tool.Url -OutFile $outputFile -UseBasicParsing | Out-Null
            Write-Color " OK" "Green"
            $success++
        }
        catch {
            Write-Color " ERROR" "Red"
        }
    }
    
    Write-Color "`n[+] $success/$($tools.Count) herramientas descargadas" "Green"
    Write-Color "[*] Ruta: $downloadPath" "Cyan"
    
    $netResponse = Read-Host "`n[?] ¿Descargar .NET Runtime (requerido)? (S/N)"
    if ($netResponse -match '^[SsYy]') {
        Write-Color "  .NET Runtime..." "White" -NoNewline
        try {
            $netUrl = "https://builds.dotnet.microsoft.com/dotnet/Sdk/9.0.306/dotnet-sdk-9.0.306-win-x64.exe"
            Invoke-WebRequest -Uri $netUrl -OutFile "$downloadPath\dotnet-runtime.exe" -UseBasicParsing | Out-Null
            Write-Color " OK" "Green"
        }
        catch {
            Write-Color " ERROR" "Red"
        }
    }
    
    Write-Host ""
    Write-Color "[*] Presiona Enter para continuar..." "White"
    $null = Read-Host
    Show-AnalyzersMenu
}

function Invoke-NirsoftTools {
    Clear-Host
    Write-Host ""
    Write-Color "[*] Descargando herramientas de Nirsoft..." "Yellow"
    
    $downloadPath = "C:\Screenshare\NirsoftTools"
    if (!(Test-Path $downloadPath)) {
        New-Item -ItemType Directory -Path $downloadPath -Force | Out-Null
    }
    
    $tools = @(
        @{Name="USBDeview"; Url="https://www.nirsoft.net/utils/usbdeview-x64.zip"},
        @{Name="NetworkUsageView"; Url="https://www.nirsoft.net/utils/networkusageview-x64.zip"},
        @{Name="AlternateStreamView"; Url="https://www.nirsoft.net/utils/alternatestreamview-x64.zip"}
    )
    
    $success = 0
    foreach ($tool in $tools) {
        Write-Color "  $($tool.Name)..." "White" -NoNewline
        try {
            $outputFile = "$downloadPath\$($tool.Name).zip"
            Invoke-WebRequest -Uri $tool.Url -OutFile $outputFile -UseBasicParsing | Out-Null
            Write-Color " OK" "Green"
            $success++
        }
        catch {
            Write-Color " ERROR" "Red"
        }
    }
    
    Write-Color "`n[+] $success/$($tools.Count) herramientas descargadas" "Green"
    Write-Color "[*] Ruta: $downloadPath" "Cyan"
    
    Write-Host ""
    Write-Color "[*] Presiona Enter para continuar..." "White"
    $null = Read-Host
    Show-AnalyzersMenu
}

function Invoke-OrbdiffTools {
    Clear-Host
    Write-Host ""
    Write-Color "[*] Descargando herramientas de Orbdiff..." "Yellow"
    
    $downloadPath = "C:\Screenshare\OrbdiffTools"
    if (!(Test-Path $downloadPath)) {
        New-Item -ItemType Directory -Path $downloadPath -Force | Out-Null
    }
    
    $tools = @(
        @{Name="Fileless"; Url="https://github.com/Orbdiff/Fileless/releases/download/v1.1/Fileless.exe"},
        @{Name="JARParser"; Url="https://github.com/Orbdiff/JARParser/releases/download/v1.2/JARParser.exe"},
        @{Name="PFTrace"; Url="https://github.com/Orbdiff/PFTrace/releases/download/v1.0.1/PFTrace.exe"}
    )
    
    $success = 0
    foreach ($tool in $tools) {
        Write-Color "  $($tool.Name)..." "White" -NoNewline
        try {
            $outputFile = "$downloadPath\$($tool.Name).exe"
            Invoke-WebRequest -Uri $tool.Url -OutFile $outputFile -UseBasicParsing | Out-Null
            Write-Color " OK" "Green"
            $success++
        }
        catch {
            Write-Color " ERROR" "Red"
        }
    }
    
    Write-Color "`n[+] $success/$($tools.Count) herramientas descargadas" "Green"
    Write-Color "[*] Ruta: $downloadPath" "Cyan"
    
    Write-Host ""
    Write-Color "[*] Presiona Enter para continuar..." "White"
    $null = Read-Host
    Show-AnalyzersMenu
}


function Invoke-JarParser {
    Write-Host ""
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
    
    Write-Host ""
    Write-Color "[*] Presiona Enter para continuar..." "White"
    $null = Read-Host
}

function Invoke-KillScreenProcesses {
    Clear-Host
    
    Write-Host ""
    Write-Host "======================================================" -ForegroundColor Green
    Write-Host "   Killer Capture Screen Processes (by Diff)" -ForegroundColor Green
    Write-Host "======================================================" -ForegroundColor Green
    Write-Host ""
    
    $targetProcesses = @(
        "chrome","firefox","msedge","opera","brave",
        "obs","obs64","streamlabs",
        "discord","discordcanary",
        "steam","steamwebhelper",
        "xboxgamebar","gamebar",
        "nvcontainer","nvstreamer",
        "amdsoftware","radeonsoftware"
    )
    
    $foundProcesses = @()
    foreach ($proc in $targetProcesses) {
        $process = Get-Process -Name $proc -ErrorAction SilentlyContinue
        if ($process) {
            $foundProcesses += $proc
        }
    }
    
    if ($foundProcesses.Count -eq 0) {
        Write-Color "[+] No se encontraron procesos sospechosos" "Green"
    }
    else {
        Write-Color "[!] Procesos encontrados:" "Yellow"
        foreach ($proc in $foundProcesses) {
            Write-Host "  - $proc.exe" -ForegroundColor Cyan
        }
        
        Write-Host ""
        $choice = Read-Host "[?] ¿Matar todos los procesos? (S/N)"
        
        if ($choice -match '^[SsYy]') {
            foreach ($proc in $foundProcesses) {
                Get-Process -Name $proc -ErrorAction SilentlyContinue | Stop-Process -Force
                Write-Host "[X] $proc.exe eliminado" -ForegroundColor Red
            }
            Write-Color "[+] Todos los procesos eliminados" "Green"
        }
        else {
            Write-Color "[*] Operación cancelada" "Yellow"
        }
    }
    
    Write-Host ""
    Write-Color "[*] Presiona Enter para continuar..." "White"
    $null = Read-Host
}


function Show-MainMenu {
    Show-Banner
    
    if ($global:isAdmin) {
        Write-Color "[+] Ejecutando como Administrador" "Green"
    }
    else {
        Write-Color "[!] Algunas funciones requieren Admin" "Yellow"
    }
    
    Write-Host ""
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host "                   MENÚ PRINCIPAL" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Color "[1] 🛠️  Herramientas de Prefetch" "Cyan"
    Write-Color "[2] 🔧 Analizadores Forenses" "Cyan"
    Write-Color "[3] ⚡ JarParser" "Cyan"
    Write-Color "[4] 🎯 Kill Screen Processes" "Cyan"
    Write-Color "[5] 📦 Otras herramientas" "Cyan"
    Write-Color "[6] 🚪 Salir" "Cyan"
    Write-Host ""
    Write-Host "--------------------------------------------------------" -ForegroundColor Gray
    
    $choice = Read-Host "[?] Selecciona opción (1-6)"
    
    switch ($choice) {
        "1" {
            Show-PrefetchMenu
            Show-MainMenu
        }
        "2" {
            Show-AnalyzersMenu
            Show-MainMenu
        }
        "3" {
            Invoke-JarParser
            Show-MainMenu
        }
        "4" {
            Invoke-KillScreenProcesses
            Show-MainMenu
        }
        "5" {
            Invoke-OtherTools
            Show-MainMenu
        }
        "6" {
            Write-Host ""
            Write-Color "[+] Saliendo... ¡Hasta pronto!" "Green"
            Write-Host ""
            Write-Host "========================================================" -ForegroundColor Cyan
            Write-Host "               discord.gg/ssa" -ForegroundColor Cyan
            Write-Host "========================================================" -ForegroundColor Cyan
            return
        }
        default {
            Write-Color "[!] Opción no válida" "Red"
            Start-Sleep -Seconds 1
            Show-MainMenu
        }
    }
}

function Invoke-OtherTools {
    Clear-Host
    
    Write-Host ""
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host "                  OTRAS HERRAMIENTAS" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Color "[1] Everything Search Engine" "White"
    Write-Color "[2] System Informer" "White"
    Write-Color "[3] FTK Imager" "White"
    Write-Color "[4] Hayabusa (Log Analysis)" "White"
    Write-Color "[5] Volver al menú principal" "White"
    Write-Host ""
    Write-Host "--------------------------------------------------------" -ForegroundColor Gray
    
    $choice = Read-Host "[?] Selecciona opción (1-5)"
    
    $downloadPath = "C:\Screenshare\OtherTools"
    if (!(Test-Path $downloadPath)) {
        New-Item -ItemType Directory -Path $downloadPath -Force | Out-Null
    }
    
    switch ($choice) {
        "1" {
            Write-Color "  Descargando Everything..." "White" -NoNewline
            try {
                $url = "https://www.voidtools.com/Everything-1.4.1.1029.x86-Setup.exe"
                Invoke-WebRequest -Uri $url -OutFile "$downloadPath\Everything-Setup.exe" -UseBasicParsing | Out-Null
                Write-Color " OK" "Green"
            }
            catch { Write-Color " ERROR" "Red" }
        }
        "2" {
            Write-Color "  Descargando System Informer..." "White" -NoNewline
            try {
                $url = "https://github.com/winsiderss/si-builds/releases/download/3.2.25297.1516/systeminformer-build-canary-setup.exe"
                Invoke-WebRequest -Uri $url -OutFile "$downloadPath\SystemInformer-Setup.exe" -UseBasicParsing | Out-Null
                Write-Color " OK" "Green"
            }
            catch { Write-Color " ERROR" "Red" }
        }
        "3" {
            Write-Color "  Descargando FTK Imager..." "White" -NoNewline
            try {
                $url = "https://d1kpmuwb7gvu1i.cloudfront.net/AccessData_FTK_Imager_4.7.1.exe"
                Invoke-WebRequest -Uri $url -OutFile "$downloadPath\FTK-Imager.exe" -UseBasicParsing | Out-Null
                Write-Color " OK" "Green"
            }
            catch { Write-Color " ERROR" "Red" }
        }
        "4" {
            Write-Color "  Descargando Hayabusa..." "White" -NoNewline
            try {
                $url = "https://github.com/Yamato-Security/hayabusa/releases/download/v3.6.0/hayabusa-3.6.0-win-x64.zip"
                Invoke-WebRequest -Uri $url -OutFile "$downloadPath\Hayabusa.zip" -UseBasicParsing | Out-Null
                Write-Color " OK" "Green"
            }
            catch { Write-Color " ERROR" "Red" }
        }
        "5" {
            return
        }
        default {
            Write-Color "[!] Opción no válida" "Red"
        }
    }
    
    if ($choice -match '^[1-4]$') {
        Write-Color "`n[+] Herramienta descargada en: $downloadPath" "Green"
        $open = Read-Host "`n[?] ¿Abrir carpeta? (S/N)"
        if ($open -match '^[SsYy]') {
            Start-Process $downloadPath
        }
    }
    
    Write-Host ""
    Write-Color "[*] Presiona Enter para continuar..." "White"
    $null = Read-Host
    Invoke-OtherTools
}


function Main {
    $global:isAdmin = Test-Administrator
    
    try {
        Show-MainMenu
    }
    catch {
        Write-Color "[!] Error crítico: $_" "Red"
        Write-Host ""
        Read-Host "Presiona Enter para salir..."
    }
}

Main
