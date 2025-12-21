# discord.gg/ssa 

$global:version = "2.3.0"
$global:isAdmin = $false


function Write-Menu {
    param(
        [string]$Text,
        [switch]$IsTitle,
        [switch]$IsOption,
        [switch]$IsWarning,
        [switch]$NoNewline
    )
    
    if ($IsTitle) {
        Write-Host $Text -ForegroundColor White -NoNewline:$NoNewline
    }
    elseif ($IsOption) {
        Write-Host $Text -ForegroundColor White -NoNewline:$NoNewline
    }
    elseif ($IsWarning) {
        Write-Host $Text -ForegroundColor Yellow -NoNewline:$NoNewline
    }
    else {
        Write-Host $Text -ForegroundColor White -NoNewline:$NoNewline
    }
}

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
        Blue = "DarkBlue"
        Cyan = "White"
        White = "White"
        Gray = "Gray"
        Magenta = "Magenta"
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
    Write-Menu "========================================================" -IsTitle
    Write-Menu "           SCREENSHARE Screenshare Alliance v$global:version" -IsTitle
    Write-Menu "                Screenshare Tool" -IsTitle
    Write-Menu "========================================================" -IsTitle
    Write-Host ""
}

function Invoke-BamParser {
    Clear-Host
    
    Write-Host ""
    Write-Menu "========================================================" -IsTitle
    Write-Menu "                    SCREENSHARE ALLIANCE" -IsTitle
    Write-Menu "                    Screenshare Tool" -IsTitle
    Write-Menu "========================================================" -IsTitle
    Write-Host ""
    Write-Menu "  Join our Discord   " -NoNewline
    Write-Menu "discord.gg/ssa" -IsWarning
    Write-Host ""
    
    if (-not $global:isAdmin) {
        Write-Color "[!] Esta herramienta requiere permisos de administrador" "Red"
        Write-Color "[*] Por favor, ejecuta este script como administrador" "Yellow"
        Write-Host ""
        Write-Color "[*] Presiona Enter para continuar..." "White"
        $null = Read-Host
        return
    }
    
    function Get-Signature {
        [CmdletBinding()]
        param (
            [string[]]$FilePath
        )

        $Existence = Test-Path -PathType "Leaf" -Path $FilePath
        $Authenticode = (Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue).Status
        $Signature = "Invalid Signature (UnknownError)"

        if ($Existence) {
            if ($Authenticode -eq "Valid") {
                $Signature = "Valid Signature"
            }
            elseif ($Authenticode -eq "NotSigned") {
                $Signature = "Invalid Signature (NotSigned)"
            }
            elseif ($Authenticode -eq "HashMismatch") {
                $Signature = "Invalid Signature (HashMismatch)"
            }
            elseif ($Authenticode -eq "NotTrusted") {
                $Signature = "Invalid Signature (NotTrusted)"
            }
            elseif ($Authenticode -eq "UnknownError") {
                $Signature = "Invalid Signature (UnknownError)"
            }
            return $Signature
        } else {
            $Signature = "File Was Not Found"
            return $Signature
        }
    }
    
    $sw = [Diagnostics.Stopwatch]::StartNew()
    
    Write-Color "[*] Analizando claves BAM del registro..." "Yellow"
    Write-Host ""
    
    if (!(Get-PSDrive -Name HKLM -PSProvider Registry)){
        try {
            New-PSDrive -Name HKLM -PSProvider Registry -Root HKEY_LOCAL_MACHINE | Out-Null
            Write-Color "[+] Unidad del registro montada" "Green"
        }
        catch {
            Write-Color "[!] Error montando HKEY_LOCAL_MACHINE" "Red"
            Write-Host ""
            Write-Color "[*] Presiona Enter para continuar..." "White"
            $null = Read-Host
            return
        }
    }
    
    $bv = ("bam", "bam\State")
    
    try {
        $Users = foreach($ii in $bv){
            Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($ii)\UserSettings\" -ErrorAction SilentlyContinue | 
            Select-Object -ExpandProperty PSChildName
        }
        
        if (-not $Users) {
            Write-Color "[!] No se encontraron entradas BAM en el registro" "Yellow"
            Write-Color "[*] Es posible que tu versión de Windows no sea compatible" "Yellow"
            Write-Host ""
            Write-Color "[*] Presiona Enter para continuar..." "White"
            $null = Read-Host
            return
        }
    }
    catch {
        Write-Color "[!] Error analizando clave BAM" "Red"
        Write-Color "[*] Versión de Windows posiblemente no compatible" "Yellow"
        Write-Host ""
        Write-Color "[*] Presiona Enter para continuar..." "White"
        $null = Read-Host
        return
    }
    
    $rpath = @("HKLM:\SYSTEM\CurrentControlSet\Services\bam\","HKLM:\SYSTEM\CurrentControlSet\Services\bam\state\")

    $UserTime = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -ErrorAction SilentlyContinue).TimeZoneKeyName
    $UserBias = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -ErrorAction SilentlyContinue).ActiveTimeBias
    $UserDay = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -ErrorAction SilentlyContinue).DaylightBias

    $BamResults = @()
    $totalUsers = $Users.Count
    $currentUser = 0
    
    foreach ($Sid in $Users) {
        $currentUser++
        Write-Color "[*] Procesando usuario $currentUser/$totalUsers..." "White"
        
        foreach($rp in $rpath){
            $pathToCheck = "$($rp)UserSettings\$Sid"
            Write-Color "  Analizando: $pathToCheck" "White"
            
            try {
                $BamItems = Get-Item -Path $pathToCheck -ErrorAction SilentlyContinue | 
                           Select-Object -ExpandProperty Property
                
                if ($BamItems) {
                    $User = ""
                    try {
                        $objSID = New-Object System.Security.Principal.SecurityIdentifier($Sid)
                        $User = $objSID.Translate([System.Security.Principal.NTAccount]).Value
                    }
                    catch {
                        $User = "Unknown"
                    }
                    
                    foreach ($Item in $BamItems) {
                        $Key = Get-ItemProperty -Path $pathToCheck -ErrorAction SilentlyContinue | 
                              Select-Object -ExpandProperty $Item
                        
                        if ($key -and $key.length -eq 24) {
                            $Hex = [System.BitConverter]::ToString($key[7..0]) -replace "-",""
                            $TimeLocal = Get-Date ([DateTime]::FromFileTime([Convert]::ToInt64($Hex, 16))) -Format "yyyy-MM-dd HH:mm:ss"
                            $TimeUTC = Get-Date ([DateTime]::FromFileTimeUtc([Convert]::ToInt64($Hex, 16))) -Format "yyyy-MM-dd HH:mm:ss"
                            $Bias = -([convert]::ToInt32([Convert]::ToString($UserBias,2),2))
                            $Day = -([convert]::ToInt32([Convert]::ToString($UserDay,2),2)) 
                            $Biasd = $Bias/60
                            $Dayd = $Day/60
                            $TimeUser = (Get-Date ([DateTime]::FromFileTimeUtc([Convert]::ToInt64($Hex, 16))).addminutes($Bias) -Format "yyyy-MM-dd HH:mm:ss") 
                            
                            $d = if((((split-path -path $item) | ConvertFrom-String -Delimiter "\\").P3) -match '\d{1}') {
                                ((split-path -path $item).Remove(23)).trimstart("\Device\HarddiskVolume")
                            } else { "" }
                            
                            $f = if((((split-path -path $item) | ConvertFrom-String -Delimiter "\\").P3) -match '\d{1}') {
                                Split-path -leaf ($item).TrimStart()
                            } else { $item }	
                            
                            $cp = if((((split-path -path $item) | ConvertFrom-String -Delimiter "\\").P3) -match '\d{1}') {
                                ($item).Remove(1,23)
                            } else { "" }
                            
                            $path = if((((split-path -path $item) | ConvertFrom-String -Delimiter "\\").P3) -match '\d{1}') {
                                Join-Path -Path "C:" -ChildPath $cp
                            } else { "" }			
                            
                            $sig = if((((split-path -path $item) | ConvertFrom-String -Delimiter "\\").P3) -match '\d{1}') {
                                Get-Signature -FilePath $path
                            } else { "" }
                            
                            $BamResults += [PSCustomObject]@{
                                'Examiner Time' = $TimeLocal
                                'Last Execution Time (UTC)' = $TimeUTC
                                'Last Execution User Time' = $TimeUser
                                'Application' = $f
                                'Path' = $path
                                'Signature' = $sig
                                'User' = $User
                                'SID' = $Sid
                                'Regpath' = $rp
                            }
                        }
                    }
                }
            }
            catch {
                Write-Color "  [!] Error procesando ruta" "Red"
            }
        }
    }
    
    $sw.Stop()
    $t = [math]::Round($sw.Elapsed.TotalMinutes, 2)
    
    if ($BamResults.Count -gt 0) {
        Write-Color "`n[+] Análisis completado" "Green"
        Write-Color "[*] Se encontraron $($BamResults.Count) entradas BAM" "White"
        Write-Color "[*] Zona horaria: $UserTime" "White"
        Write-Color "[*] Tiempo de ejecución: $t minutos" "Yellow"
        Write-Host ""
        
        try {
            $BamResults | Out-GridView -Title "BAM Parser - $($BamResults.Count) entradas encontradas | Zona horaria: $UserTime | Tiempo: $t minutos" -PassThru
        }
        catch {
            Write-Color "[!] No se pudo mostrar la interfaz gráfica" "Red"
            Write-Color "[*] Mostrando primeros 10 resultados en consola:" "Yellow"
            Write-Host ""
            
            $BamResults | Select-Object -First 10 | Format-Table -AutoSize
        }
    }
    else {
        Write-Color "[!] No se encontraron datos BAM" "Yellow"
        Write-Color "[*] Tiempo de ejecución: $t minutos" "Yellow"
    }
    
    Write-Host ""
    Write-Color "[*] Presiona Enter para continuar..." "White"
    $null = Read-Host
}

function Show-PrefetchMenu {
    Clear-Host
    
    Write-Host ""
    Write-Menu "========================================================" -IsTitle
    Write-Menu "                   HERRAMIENTAS PREFETCH" -IsTitle
    Write-Menu "========================================================" -IsTitle
    Write-Host ""
    
    Write-Menu "[1] Descargar PrefetchView++ (Orbdiff)" -IsOption
    Write-Menu "[2] Descargar WinPrefetchView (Nirsoft)" -IsOption
    Write-Menu "[3] Descargar Prefetch Parser (Spokwn)" -IsOption
    Write-Menu "[4] Analizar prefetch local" -IsOption
    Write-Menu "[5] Descargar TODAS las herramientas Prefetch" -IsOption
    Write-Menu "[6] Volver al menú principal" -IsOption
    Write-Host ""
    Write-Menu "--------------------------------------------------------" -IsTitle
    
    $choice = Read-Host "[?] Selecciona opción (1-6)"
    
    $downloadPath = "C:\Screenshare\PrefetchTools"
    if (!(Test-Path $downloadPath)) {
        New-Item -ItemType Directory -Path $downloadPath -Force | Out-Null
    }
    
    switch ($choice) {
        "1" {
            Write-Host ""
            Write-Color "[*] Descargando PrefetchView++ de Orbdiff..." "Yellow"
            
            try {
                $url = "https://github.com/Orbdiff/PrefetchView/releases/download/v1.4/PrefetchView++.exe"
                $outputFile = "$downloadPath\PrefetchView++.exe"
                
                Write-Color "  Descargando..." "White" -NoNewline
                Invoke-WebRequest -Uri $url -OutFile $outputFile -UseBasicParsing | Out-Null
                Write-Color " OK" "Green"
                
                Write-Color "[+] Herramienta descargada en: $downloadPath" "Green"
            }
            catch {
                Write-Color "[!] Error al descargar: $_" "Red"
            }
        }
        "2" {
            Write-Host ""
            Write-Color "[*] Descargando WinPrefetchView de Nirsoft..." "Yellow"
            
            try {
                $url = "https://www.nirsoft.net/utils/winprefetchview-x64.zip"
                $outputFile = "$downloadPath\winprefetchview-x64.zip"
                
                Write-Color "  Descargando..." "White" -NoNewline
                Invoke-WebRequest -Uri $url -OutFile $outputFile -UseBasicParsing | Out-Null
                
                Expand-Archive -Path $outputFile -DestinationPath $downloadPath -Force | Out-Null
                Remove-Item $outputFile -Force | Out-Null
                
                Write-Color " OK" "Green"
                Write-Color "[+] Herramienta descargada y extraída en: $downloadPath" "Green"
            }
            catch {
                Write-Color "[!] Error al descargar: $_" "Red"
            }
        }
        "3" {
            Write-Host ""
            Write-Color "[*] Descargando Prefetch Parser de Spokwn..." "Yellow"
            
            try {
                $url = "https://github.com/spokwn/prefetch-parser/releases/download/v1.5.5/PrefetchParser.exe"
                $outputFile = "$downloadPath\PrefetchParser.exe"
                
                Write-Color "  Descargando..." "White" -NoNewline
                Invoke-WebRequest -Uri $url -OutFile $outputFile -UseBasicParsing | Out-Null
                Write-Color " OK" "Green"
                
                Write-Color "[+] Herramienta descargada en: $downloadPath" "Green"
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
                    Write-Color "Últimos archivos Prefetch:" "White"
                    
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
            Write-Host ""
            Write-Color "[*] Descargando TODAS las herramientas Prefetch..." "Yellow"
            
            $tools = @(
                @{Name="PrefetchView++"; Url="https://github.com/Orbdiff/PrefetchView/releases/download/v1.4/PrefetchView++.exe"},
                @{Name="WinPrefetchView"; Url="https://www.nirsoft.net/utils/winprefetchview-x64.zip"},
                @{Name="PrefetchParser"; Url="https://github.com/spokwn/prefetch-parser/releases/download/v1.5.5/PrefetchParser.exe"}
            )
            
            $success = 0
            foreach ($tool in $tools) {
                Write-Color "  $($tool.Name)..." "White" -NoNewline
                try {
                    if ($tool.Url -like "*.zip") {
                        $outputFile = "$downloadPath\$($tool.Name).zip"
                        Invoke-WebRequest -Uri $tool.Url -OutFile $outputFile -UseBasicParsing | Out-Null
                        Expand-Archive -Path $outputFile -DestinationPath $downloadPath -Force | Out-Null
                        Remove-Item $outputFile -Force | Out-Null
                    }
                    else {
                        $outputFile = "$downloadPath\$($tool.Name).exe"
                        Invoke-WebRequest -Uri $tool.Url -OutFile $outputFile -UseBasicParsing | Out-Null
                    }
                    Write-Color " OK" "Green"
                    $success++
                }
                catch {
                    Write-Color " ERROR" "Red"
                }
            }
            
            Write-Color "`n[+] $success/$($tools.Count) herramientas descargadas" "Green"
        }
        "6" {
            return
        }
        default {
            Write-Color "[!] Opción no válida" "Red"
        }
    }
    
    if ($choice -match '^[1-5]$') {
        $open = Read-Host "`n[?] ¿Abrir carpeta de descargas? (S/N)"
        if ($open -match '^[SsYy]') {
            Start-Process $downloadPath
        }
    }
    
    Write-Host ""
    Write-Color "[*] Presiona Enter para continuar..." "White"
    $null = Read-Host
    Show-PrefetchMenu
}

function Show-DownloadSSTools {
    Clear-Host
    
    Write-Host ""
    Write-Menu "========================================================" -IsTitle
    Write-Menu "           DESCARGAR HERRAMIENTAS SS" -IsTitle
    Write-Menu "========================================================" -IsTitle
    Write-Host ""
    
    Write-Menu "[1] Descargar TODAS las herramientas" -IsOption
    Write-Menu "[2] Herramientas de Eric Zimmerman" -IsOption
    Write-Menu "[3] Herramientas de Nirsoft" -IsOption
    Write-Menu "[4] Herramientas de Spokwn" -IsOption
    Write-Menu "[5] Herramientas de Orbdiff" -IsOption
    Write-Menu "[6] Otras herramientas útiles" -IsOption
    Write-Menu "[7] Volver al menú principal" -IsOption
    Write-Host ""
    Write-Menu "--------------------------------------------------------" -IsTitle
    
    $choice = Read-Host "[?] Selecciona opción (1-7)"
    
    switch ($choice) {
        "1" {
            Invoke-DownloadAllTools
        }
        "2" {
            Show-ZimmermanToolsMenu
        }
        "3" {
            Show-NirsoftToolsMenu
        }
        "4" {
            Show-SpokwnToolsMenu
        }
        "5" {
            Show-OrbdiffToolsMenu
        }
        "6" {
            Show-OtherToolsMenu
        }
        "7" {
            return
        }
        default {
            Write-Color "[!] Opción no válida" "Red"
            Start-Sleep -Seconds 1
            Show-DownloadSSTools
        }
    }
}

function Show-ZimmermanToolsMenu {
    Clear-Host
    
    $zimmermanTools = @(
        @{ID=1; Name="AmcacheParser"; Url="https://download.ericzimmermanstools.com/net9/AmcacheParser.zip"},
        @{ID=2; Name="AppCompatCacheParser"; Url="https://download.ericzimmermanstools.com/net9/AppCompatCacheParser.zip"},
        @{ID=3; Name="RegistryExplorer"; Url="https://download.ericzimmermanstools.com/net9/RegistryExplorer.zip"},
        @{ID=4; Name="MFTECmd"; Url="https://download.ericzimmermanstools.com/net9/MFTECmd.zip"},
        @{ID=5; Name="PECmd"; Url="https://download.ericzimmermanstools.com/net9/PECmd.zip"},
        @{ID=6; Name="TimelineExplorer"; Url="https://download.ericzimmermanstools.com/net9/TimelineExplorer.zip"},
        @{ID=7; Name="SrumECmd"; Url="https://download.ericzimmermanstools.com/net9/SrumECmd.zip"},
        @{ID=8; Name="JumpListExplorer"; Url="https://download.ericzimmermanstools.com/net9/JumpListExplorer.zip"}
    )
    
    Write-Host ""
    Write-Menu "========================================================" -IsTitle
    Write-Menu "        HERRAMIENTAS DE ERIC ZIMMERMAN" -IsTitle
    Write-Menu "========================================================" -IsTitle
    Write-Host ""
    
    foreach ($tool in $zimmermanTools) {
        Write-Menu "[$($tool.ID)] $($tool.Name)" -IsOption
    }
    
    Write-Menu "[A] Descargar TODAS las herramientas Zimmerman" -IsOption
    Write-Menu "[X] Volver al menú anterior" -IsOption
    Write-Host ""
    Write-Menu "--------------------------------------------------------" -IsTitle
    
    $selection = Read-Host "[?] Selecciona herramienta (1-8, A, X)"
    
    $downloadPath = "C:\Screenshare\ZimmermanTools"
    if (!(Test-Path $downloadPath)) {
        New-Item -ItemType Directory -Path $downloadPath -Force | Out-Null
    }
    
    if ($selection.ToUpper() -eq "A") {
        Write-Host ""
        Write-Color "[*] Descargando TODAS las herramientas Zimmerman..." "Yellow"
        
        $success = 0
        foreach ($tool in $zimmermanTools) {
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
        
        Write-Color "`n[+] $success/$($zimmermanTools.Count) herramientas descargadas" "Green"
        
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
    }
    elseif ($selection.ToUpper() -eq "X") {
        Show-DownloadSSTools
        return
    }
    elseif ($selection -match '^\d+$' -and [int]$selection -ge 1 -and [int]$selection -le $zimmermanTools.Count) {
        $tool = $zimmermanTools | Where-Object { $_.ID -eq [int]$selection } | Select-Object -First 1
        
        Write-Host ""
        Write-Color "[*] Descargando $($tool.Name)..." "Yellow"
        
        Write-Color "  Descargando..." "White" -NoNewline
        try {
            $outputFile = "$downloadPath\$($tool.Name).zip"
            Invoke-WebRequest -Uri $tool.Url -OutFile $outputFile -UseBasicParsing | Out-Null
            Write-Color " OK" "Green"
            Write-Color "[+] Herramienta descargada en: $downloadPath" "Green"
        }
        catch {
            Write-Color " ERROR" "Red"
        }
    }
    else {
        Write-Color "[!] Selección no válida" "Red"
        Start-Sleep -Seconds 1
        Show-ZimmermanToolsMenu
        return
    }
    
    Write-Color "`n[*] Ruta: $downloadPath" "White"
    
    $open = Read-Host "`n[?] ¿Abrir carpeta de descargas? (S/N)"
    if ($open -match '^[SsYy]') {
        Start-Process $downloadPath
    }
    
    Write-Host ""
    Write-Color "[*] Presiona Enter para continuar..." "White"
    $null = Read-Host
    Show-ZimmermanToolsMenu
}

function Show-NirsoftToolsMenu {
    Clear-Host
    
   
    $nirsoftTools = @(
        @{ID=1; Name="LastActivityView"; Url="https://www.nirsoft.net/utils/lastactivityview.zip"; Description="Muestra el historial de actividad del sistema"},
        @{ID=2; Name="UserAssistView"; Url="https://www.nirsoft.net/utils/userassistview-x64.zip"; Description="Analiza claves UserAssist del registro"},
        @{ID=3; Name="USBDeview"; Url="https://www.nirsoft.net/utils/usbdeview-x64.zip"; Description="Muestra dispositivos USB conectados"},
        @{ID=4; Name="NetworkUsageView"; Url="https://www.nirsoft.net/utils/networkusageview-x64.zip"; Description="Monitor de uso de red"},
        @{ID=5; Name="AlternateStreamView"; Url="https://www.nirsoft.net/utils/alternatestreamview-x64.zip"; Description="Detecta flujos alternos ADS"},
        @{ID=6; Name="WinPrefetchView"; Url="https://www.nirsoft.net/utils/winprefetchview-x64.zip"; Description="Analiza archivos prefetch"},
        @{ID=7; Name="ShellBagsView"; Url="https://www.nirsoft.net/utils/shellbagsview-x64.zip"; Description="Analiza ShellBags (historial de carpetas)"},
        @{ID=8; Name="TurnedOnTimesView"; Url="https://www.nirsoft.net/utils/turnedontimesview-x64.zip"; Description="Muestra horas de encendido/apagado"}
    )
    
    Write-Host ""
    Write-Menu "========================================================" -IsTitle
    Write-Menu "           HERRAMIENTAS DE NIRSOFT" -IsTitle
    Write-Menu "========================================================" -IsTitle
    Write-Host ""
    
    foreach ($tool in $nirsoftTools) {
        Write-Menu "[$($tool.ID)] $($tool.Name)" -IsOption
        Write-Host "     $($tool.Description)" -ForegroundColor Gray
    }
    
    Write-Menu "[A] Descargar TODAS las herramientas Nirsoft" -IsOption
    Write-Menu "[X] Volver al menú anterior" -IsOption
    Write-Host ""
    Write-Menu "--------------------------------------------------------" -IsTitle
    
    $selection = Read-Host "[?] Selecciona herramienta (1-8, A, X)"
    
    $downloadPath = "C:\Screenshare\NirsoftTools"
    if (!(Test-Path $downloadPath)) {
        New-Item -ItemType Directory -Path $downloadPath -Force | Out-Null
    }
    
    if ($selection.ToUpper() -eq "A") {
        Write-Host ""
        Write-Color "[*] Descargando TODAS las herramientas Nirsoft..." "Yellow"
        
        $success = 0
        foreach ($tool in $nirsoftTools) {
            Write-Color "  $($tool.Name)..." "White" -NoNewline
            try {
                $outputFile = "$downloadPath\$($tool.Name).zip"
                Invoke-WebRequest -Uri $tool.Url -OutFile $outputFile -UseBasicParsing | Out-Null
                
                Expand-Archive -Path $outputFile -DestinationPath $downloadPath -Force | Out-Null
                Remove-Item $outputFile -Force | Out-Null
                
                Write-Color " OK" "Green"
                $success++
            }
            catch {
                Write-Color " ERROR" "Red"
            }
        }
        
        Write-Color "`n[+] $success/$($nirsoftTools.Count) herramientas descargadas" "Green"
    }
    elseif ($selection.ToUpper() -eq "X") {
        Show-DownloadSSTools
        return
    }
    elseif ($selection -match '^\d+$' -and [int]$selection -ge 1 -and [int]$selection -le $nirsoftTools.Count) {
        $tool = $nirsoftTools | Where-Object { $_.ID -eq [int]$selection } | Select-Object -First 1
        
        Write-Host ""
        Write-Color "[*] Descargando $($tool.Name)..." "Yellow"
        Write-Color "[*] Descripción: $($tool.Description)" "White"
        
        Write-Color "  Descargando..." "White" -NoNewline
        try {
            $outputFile = "$downloadPath\$($tool.Name).zip"
            Invoke-WebRequest -Uri $tool.Url -OutFile $outputFile -UseBasicParsing | Out-Null
            
            Expand-Archive -Path $outputFile -DestinationPath $downloadPath -Force | Out-Null
            Remove-Item $outputFile -Force | Out-Null
            
            Write-Color " OK" "Green"
            Write-Color "[+] Herramienta descargada y extraída en: $downloadPath" "Green"
        }
        catch {
            Write-Color " ERROR" "Red"
        }
    }
    else {
        Write-Color "[!] Selección no válida" "Red"
        Start-Sleep -Seconds 1
        Show-NirsoftToolsMenu
        return
    }
    
    Write-Color "`n[*] Ruta: $downloadPath" "White"
    
    $open = Read-Host "`n[?] ¿Abrir carpeta de descargas? (S/N)"
    if ($open -match '^[SsYy]') {
        Start-Process $downloadPath
    }
    
    Write-Host ""
    Write-Color "[*] Presiona Enter para continuar..." "White"
    $null = Read-Host
    Show-NirsoftToolsMenu
}

function Show-SpokwnToolsMenu {
    Clear-Host
    
    $spokwnTools = @(
        @{ID=1; Name="KernelLiveDumpTool"; Url="https://github.com/spokwn/KernelLiveDumpTool/releases/download/v1.1/KernelLiveDumpTool.exe"},
        @{ID=2; Name="BAMParser"; Url="https://github.com/spokwn/BAM-parser/releases/download/v1.2.9/BAMParser.exe"},
        @{ID=3; Name="PathsParser"; Url="https://github.com/spokwn/PathsParser/releases/download/v1.2/PathsParser.exe"},
        @{ID=4; Name="PrefetchParser"; Url="https://github.com/spokwn/prefetch-parser/releases/download/v1.5.5/PrefetchParser.exe"},
        @{ID=5; Name="ActivitiesCacheParser"; Url="https://github.com/spokwn/ActivitiesCache-execution/releases/download/v0.6.5/ActivitiesCacheParser.exe"},
        @{ID=6; Name="JournalTrace"; Url="https://github.com/spokwn/JournalTrace/releases/download/1.2/JournalTrace.exe"},
        @{ID=7; Name="Tool (espouken)"; Url="https://github.com/spokwn/Tool/releases/download/v1.1.3/espouken.exe"},
        @{ID=8; Name="PcaSvcExecuted"; Url="https://github.com/spokwn/pcasvc-executed/releases/download/v0.8.7/PcaSvcExecuted.exe"}
    )
    
    Write-Host ""
    Write-Menu "========================================================" -IsTitle
    Write-Menu "           HERRAMIENTAS DE SPOKWN" -IsTitle
    Write-Menu "========================================================" -IsTitle
    Write-Host ""
    
    foreach ($tool in $spokwnTools) {
        Write-Menu "[$($tool.ID)] $($tool.Name)" -IsOption
    }
    
    Write-Menu "[A] Descargar TODAS las herramientas Spokwn" -IsOption
    Write-Menu "[X] Volver al menú anterior" -IsOption
    Write-Host ""
    Write-Menu "--------------------------------------------------------" -IsTitle
    
    $selection = Read-Host "[?] Selecciona herramienta (1-8, A, X)"
    
    $downloadPath = "C:\Screenshare\SpokwnTools"
    if (!(Test-Path $downloadPath)) {
        New-Item -ItemType Directory -Path $downloadPath -Force | Out-Null
    }
    
    if ($selection.ToUpper() -eq "A") {
        Write-Host ""
        Write-Color "[*] Descargando TODAS las herramientas Spokwn..." "Yellow"
        
        $success = 0
        foreach ($tool in $spokwnTools) {
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
        
        Write-Color "`n[+] $success/$($spokwnTools.Count) herramientas descargadas" "Green"
    }
    elseif ($selection.ToUpper() -eq "X") {
        Show-DownloadSSTools
        return
    }
    elseif ($selection -match '^\d+$' -and [int]$selection -ge 1 -and [int]$selection -le $spokwnTools.Count) {
        $tool = $spokwnTools | Where-Object { $_.ID -eq [int]$selection } | Select-Object -First 1
        
        Write-Host ""
        Write-Color "[*] Descargando $($tool.Name)..." "Yellow"
        
        Write-Color "  Descargando..." "White" -NoNewline
        try {
            $outputFile = "$downloadPath\$($tool.Name).exe"
            Invoke-WebRequest -Uri $tool.Url -OutFile $outputFile -UseBasicParsing | Out-Null
            Write-Color " OK" "Green"
            Write-Color "[+] Herramienta descargada en: $downloadPath" "Green"
        }
        catch {
            Write-Color " ERROR" "Red"
        }
    }
    else {
        Write-Color "[!] Selección no válida" "Red"
        Start-Sleep -Seconds 1
        Show-SpokwnToolsMenu
        return
    }
    
    Write-Color "`n[*] Ruta: $downloadPath" "White"
    
    $open = Read-Host "`n[?] ¿Abrir carpeta de descargas? (S/N)"
    if ($open -match '^[SsYy]') {
        Start-Process $downloadPath
    }
    
    Write-Host ""
    Write-Color "[*] Presiona Enter para continuar..." "White"
    $null = Read-Host
    Show-SpokwnToolsMenu
}

function Show-OrbdiffToolsMenu {
    Clear-Host
    
    $orbdiffTools = @(
        @{ID=1; Name="Fileless"; Url="https://github.com/Orbdiff/Fileless/releases/download/v1.1/Fileless.exe"},
        @{ID=2; Name="JARParser"; Url="https://github.com/Orbdiff/JARParser/releases/download/v1.2/JARParser.exe"},
        @{ID=3; Name="PFTrace"; Url="https://github.com/Orbdiff/PFTrace/releases/download/v1.0.1/PFTrace.exe"},
        @{ID=4; Name="PrefetchView++"; Url="https://github.com/Orbdiff/PrefetchView/releases/download/v1.4/PrefetchView++.exe"},
        @{ID=5; Name="BamDeletedKeys"; Url="https://github.com/Orbdiff/BamDeletedKeys/releases/download/v1.0/BamDeletedKeys.exe"}
    )
    
    Write-Host ""
    Write-Menu "========================================================" -IsTitle
    Write-Menu "           HERRAMIENTAS DE ORBDIFF" -IsTitle
    Write-Menu "========================================================" -IsTitle
    Write-Host ""
    
    foreach ($tool in $orbdiffTools) {
        Write-Menu "[$($tool.ID)] $($tool.Name)" -IsOption
    }
    
    Write-Menu "[A] Descargar TODAS las herramientas Orbdiff" -IsOption
    Write-Menu "[X] Volver al menú anterior" -IsOption
    Write-Host ""
    Write-Menu "--------------------------------------------------------" -IsTitle
    
    $selection = Read-Host "[?] Selecciona herramienta (1-5, A, X)"
    
    $downloadPath = "C:\Screenshare\OrbdiffTools"
    if (!(Test-Path $downloadPath)) {
        New-Item -ItemType Directory -Path $downloadPath -Force | Out-Null
    }
    
    if ($selection.ToUpper() -eq "A") {
        Write-Host ""
        Write-Color "[*] Descargando TODAS las herramientas Orbdiff..." "Yellow"
        
        $success = 0
        foreach ($tool in $orbdiffTools) {
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
        
        Write-Color "`n[+] $success/$($orbdiffTools.Count) herramientas descargadas" "Green"
    }
    elseif ($selection.ToUpper() -eq "X") {
        Show-DownloadSSTools
        return
    }
    elseif ($selection -match '^\d+$' -and [int]$selection -ge 1 -and [int]$selection -le $orbdiffTools.Count) {
        $tool = $orbdiffTools | Where-Object { $_.ID -eq [int]$selection } | Select-Object -First 1
        
        Write-Host ""
        Write-Color "[*] Descargando $($tool.Name)..." "Yellow"
        
        Write-Color "  Descargando..." "White" -NoNewline
        try {
            $outputFile = "$downloadPath\$($tool.Name).exe"
            Invoke-WebRequest -Uri $tool.Url -OutFile $outputFile -UseBasicParsing | Out-Null
            Write-Color " OK" "Green"
            Write-Color "[+] Herramienta descargada en: $downloadPath" "Green"
        }
        catch {
            Write-Color " ERROR" "Red"
        }
    }
    else {
        Write-Color "[!] Selección no válida" "Red"
        Start-Sleep -Seconds 1
        Show-OrbdiffToolsMenu
        return
    }
    
    Write-Color "`n[*] Ruta: $downloadPath" "White"
    
    $open = Read-Host "`n[?] ¿Abrir carpeta de descargas? (S/N)"
    if ($open -match '^[SsYy]') {
        Start-Process $downloadPath
    }
    
    Write-Host ""
    Write-Color "[*] Presiona Enter para continuar..." "White"
    $null = Read-Host
    Show-OrbdiffToolsMenu
}

function Show-OtherToolsMenu {
    Clear-Host
    
    $otherTools = @(
        @{ID=1; Name="Everything Search"; Url="https://www.voidtools.com/Everything-1.4.1.1029.x86-Setup.exe"},
        @{ID=2; Name="System Informer"; Url="https://github.com/winsiderss/si-builds/releases/download/3.2.25297.1516/systeminformer-build-canary-setup.exe"},
        @{ID=3; Name="FTK Imager"; Url="https://d1kpmuwb7gvu1i.cloudfront.net/AccessData_FTK_Imager_4.7.1.exe"},
        @{ID=4; Name="Hayabusa"; Url="https://github.com/Yamato-Security/hayabusa/releases/download/v3.6.0/hayabusa-3.6.0-win-x64.zip"},
        @{ID=5; Name=".NET Runtime"; Url="https://builds.dotnet.microsoft.com/dotnet/Sdk/9.0.306/dotnet-sdk-9.0.306-win-x64.exe"}
    )
    
    Write-Host ""
    Write-Menu "========================================================" -IsTitle
    Write-Menu "          OTRAS HERRAMIENTAS ÚTILES" -IsTitle
    Write-Menu "========================================================" -IsTitle
    Write-Host ""
    
    foreach ($tool in $otherTools) {
        Write-Menu "[$($tool.ID)] $($tool.Name)" -IsOption
    }
    
    Write-Menu "[A] Descargar TODAS las otras herramientas" -IsOption
    Write-Menu "[X] Volver al menú anterior" -IsOption
    Write-Host ""
    Write-Menu "--------------------------------------------------------" -IsTitle
    
    $selection = Read-Host "[?] Selecciona herramienta (1-5, A, X)"
    
    $downloadPath = "C:\Screenshare\OtherTools"
    if (!(Test-Path $downloadPath)) {
        New-Item -ItemType Directory -Path $downloadPath -Force | Out-Null
    }
    
    if ($selection.ToUpper() -eq "A") {
        Write-Host ""
        Write-Color "[*] Descargando TODAS las otras herramientas..." "Yellow"
        
        $success = 0
        foreach ($tool in $otherTools) {
            Write-Color "  $($tool.Name)..." "White" -NoNewline
            try {
                if ($tool.Url -like "*.zip") {
                    $outputFile = "$downloadPath\$($tool.Name).zip"
                    Invoke-WebRequest -Uri $tool.Url -OutFile $outputFile -UseBasicParsing | Out-Null
                    Expand-Archive -Path $outputFile -DestinationPath $downloadPath -Force | Out-Null
                    Remove-Item $outputFile -Force | Out-Null
                }
                else {
                    $outputFile = "$downloadPath\$($tool.Name).exe"
                    Invoke-WebRequest -Uri $tool.Url -OutFile $outputFile -UseBasicParsing | Out-Null
                }
                Write-Color " OK" "Green"
                $success++
            }
            catch {
                Write-Color " ERROR" "Red"
            }
        }
        
        Write-Color "`n[+] $success/$($otherTools.Count) herramientas descargadas" "Green"
    }
    elseif ($selection.ToUpper() -eq "X") {
        Show-DownloadSSTools
        return
    }
    elseif ($selection -match '^\d+$' -and [int]$selection -ge 1 -and [int]$selection -le $otherTools.Count) {
        $tool = $otherTools | Where-Object { $_.ID -eq [int]$selection } | Select-Object -First 1
        
        Write-Host ""
        Write-Color "[*] Descargando $($tool.Name)..." "Yellow"
        
        Write-Color "  Descargando..." "White" -NoNewline
        try {
            if ($tool.Url -like "*.zip") {
                $outputFile = "$downloadPath\$($tool.Name).zip"
                Invoke-WebRequest -Uri $tool.Url -OutFile $outputFile -UseBasicParsing | Out-Null
                Expand-Archive -Path $outputFile -DestinationPath $downloadPath -Force | Out-Null
                Remove-Item $outputFile -Force | Out-Null
                Write-Color " OK" "Green"
                Write-Color "[+] Herramienta descargada y extraída en: $downloadPath" "Green"
            }
            else {
                $outputFile = "$downloadPath\$($tool.Name).exe"
                Invoke-WebRequest -Uri $tool.Url -OutFile $outputFile -UseBasicParsing | Out-Null
                Write-Color " OK" "Green"
                Write-Color "[+] Herramienta descargada en: $downloadPath" "Green"
            }
        }
        catch {
            Write-Color " ERROR" "Red"
        }
    }
    else {
        Write-Color "[!] Selección no válida" "Red"
        Start-Sleep -Seconds 1
        Show-OtherToolsMenu
        return
    }
    
    Write-Color "`n[*] Ruta: $downloadPath" "White"
    
    $open = Read-Host "`n[?] ¿Abrir carpeta de descargas? (S/N)"
    if ($open -match '^[SsYy]') {
        Start-Process $downloadPath
    }
    
    Write-Host ""
    Write-Color "[*] Presiona Enter para continuar..." "White"
    $null = Read-Host
    Show-OtherToolsMenu
}

function Invoke-DownloadAllTools {
    Clear-Host
    Write-Host ""
    Write-Color "[*] Descargando TODAS las herramientas SS..." "Yellow"
    Write-Color "[!] Esto puede tomar varios minutos" "Yellow"
    Write-Host ""
    
    $mainPath = "C:\Screenshare"
    if (!(Test-Path $mainPath)) {
        New-Item -ItemType Directory -Path $mainPath -Force | Out-Null
    }
    
    Write-Color "Carpeta principal: $mainPath" "White"
    Write-Host ""
    
    $totalSuccess = 0
    $totalTools = 0
    
    Write-Color "[*] Descargando herramientas Zimmerman..." "Yellow"
    $zimmermanTools = @(
        @{Name="AmcacheParser"; Url="https://download.ericzimmermanstools.com/net9/AmcacheParser.zip"},
        @{Name="RegistryExplorer"; Url="https://download.ericzimmermanstools.com/net9/RegistryExplorer.zip"}
    )
    foreach ($tool in $zimmermanTools) {
        Write-Color "  $($tool.Name)..." "White" -NoNewline
        try {
            $path = "C:\Screenshare\ZimmermanTools"
            if (!(Test-Path $path)) { New-Item -ItemType Directory -Path $path -Force | Out-Null }
            Invoke-WebRequest -Uri $tool.Url -OutFile "$path\$($tool.Name).zip" -UseBasicParsing | Out-Null
            Write-Color " OK" "Green"
            $totalSuccess++
        } catch { Write-Color " ERROR" "Red" }
        $totalTools++
    }
    
    Write-Color "[*] Descargando herramientas Nirsoft..." "Yellow"
   
    $nirsoftTools = @(
        @{Name="LastActivityView"; Url="https://www.nirsoft.net/utils/lastactivityview.zip"},
        @{Name="UserAssistView"; Url="https://www.nirsoft.net/utils/userassistview-x64.zip"},
        @{Name="USBDeview"; Url="https://www.nirsoft.net/utils/usbdeview-x64.zip"},
        @{Name="WinPrefetchView"; Url="https://www.nirsoft.net/utils/winprefetchview-x64.zip"}
    )
    foreach ($tool in $nirsoftTools) {
        Write-Color "  $($tool.Name)..." "White" -NoNewline
        try {
            $path = "C:\Screenshare\NirsoftTools"
            if (!(Test-Path $path)) { New-Item -ItemType Directory -Path $path -Force | Out-Null }
            Invoke-WebRequest -Uri $tool.Url -OutFile "$path\$($tool.Name).zip" -UseBasicParsing | Out-Null
            Write-Color " OK" "Green"
            $totalSuccess++
        } catch { Write-Color " ERROR" "Red" }
        $totalTools++
    }
    
    Write-Color "[*] Descargando herramientas Spokwn..." "Yellow"
    $spokwnTools = @(
        @{Name="BAMParser"; Url="https://github.com/spokwn/BAM-parser/releases/download/v1.2.9/BAMParser.exe"},
        @{Name="PrefetchParser"; Url="https://github.com/spokwn/prefetch-parser/releases/download/v1.5.5/PrefetchParser.exe"}
    )
    foreach ($tool in $spokwnTools) {
        Write-Color "  $($tool.Name)..." "White" -NoNewline
        try {
            $path = "C:\Screenshare\SpokwnTools"
            if (!(Test-Path $path)) { New-Item -ItemType Directory -Path $path -Force | Out-Null }
            Invoke-WebRequest -Uri $tool.Url -OutFile "$path\$($tool.Name).exe" -UseBasicParsing | Out-Null
            Write-Color " OK" "Green"
            $totalSuccess++
        } catch { Write-Color " ERROR" "Red" }
        $totalTools++
    }
    
    Write-Color "`n[+] $totalSuccess/$totalTools herramientas principales descargadas" "Green"
    Write-Color "[*] Ubicación: $mainPath" "White"
    
    $open = Read-Host "`n[?] ¿Abrir carpeta principal? (S/N)"
    if ($open -match '^[SsYy]') {
        Start-Process $mainPath
    }
    
    Write-Host ""
    Write-Color "[*] Presiona Enter para continuar..." "White"
    $null = Read-Host
    Show-DownloadSSTools
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
    Write-Menu "======================================================" -IsTitle
    Write-Menu "   Killer Capture Screen Processes (by Diff)" -IsTitle
    Write-Menu "======================================================" -IsTitle
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
            Write-Host "  - $proc.exe" -ForegroundColor White
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
    Write-Menu "========================================================" -IsTitle
    Write-Menu "                   MENÚ PRINCIPAL" -IsTitle
    Write-Menu "========================================================" -IsTitle
    Write-Host ""
    
    Write-Menu "[1] 🛠️ Herramientas de Prefetch" -IsOption
    Write-Menu "[2] 📥 Descargar SS Tools" -IsOption
    Write-Menu "[3] 🔍 Bam-Parser      " -IsOption
    Write-Menu "[4] ⚡ JarParser" -IsOption
    Write-Menu "[5] 🎯 Kill Screen Processes" -IsOption
    Write-Menu "[6] 🚪 Salir" -IsOption
    Write-Host ""
    Write-Menu "--------------------------------------------------------" -IsTitle
    
    $choice = Read-Host "[?] Selecciona opción (1-6)"
    
    switch ($choice) {
        "1" {
            Show-PrefetchMenu
            Show-MainMenu
        }
        "2" {
            Show-DownloadSSTools
            Show-MainMenu
        }
        "3" {
            Invoke-BamParser
            Show-MainMenu
        }
        "4" {
            Invoke-JarParser
            Show-MainMenu
        }
        "5" {
            Invoke-KillScreenProcesses
            Show-MainMenu
        }
        "6" {
            Write-Host ""
            Write-Color "[+] Saliendo... ¡Hasta pronto!" "Green"
            Write-Host ""
            Write-Menu "========================================================" -IsTitle
            Write-Menu "               discord.gg/ssa" -IsTitle
            Write-Menu "========================================================" -IsTitle
            return
        }
        default {
            Write-Color "[!] Opción no válida" "Red"
            Start-Sleep -Seconds 1
            Show-MainMenu
        }
    }
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

