# discord.gg/ssa 

$global:version = "2.2.0"
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
    Write-Host "           SCREENSHARE ALLIANCE v$global:version" -ForegroundColor Cyan
    Write-Host "                discord.gg/ssa" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host ""
}


function Invoke-BamParser {
    Clear-Host
    
    Write-Host ""
    Write-Host "========================================================" -ForegroundColor Red
    Write-Host "                    SCREENSHARE ALLIANCE" -ForegroundColor Red
    Write-Host "                    discord.gg/ssa" -ForegroundColor Red
    Write-Host "========================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Join our Discord" -NoNewline
    Write-Host "discord.gg/ssa" -ForegroundColor Red
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
        Write-Color "[*] Procesando usuario $currentUser/$totalUsers..." "Cyan"
        
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
        Write-Color "[*] Se encontraron $($BamResults.Count) entradas BAM" "Cyan"
        Write-Color "[*] Zona horaria: $UserTime" "Cyan"
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
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host "                   HERRAMIENTAS PREFETCH" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Color "[1] Descargar PrefetchView++ (Orbdiff)" "White"
    Write-Color "[2] Descargar WinPrefetchView (Nirsoft)" "White"
    Write-Color "[3] Descargar Prefetch Parser (Spokwn)" "White"
    Write-Color "[4] Analizar prefetch local" "White"
    Write-Color "[5] Descargar TODAS las herramientas Prefetch" "White"
    Write-Color "[6] Volver al menú principal" "White"
    Write-Host ""
    Write-Host "--------------------------------------------------------" -ForegroundColor Gray
    
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
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host "           DESCARGAR HERRAMIENTAS SS" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Color "[1] Descargar TODAS las herramientas" "Cyan"
    Write-Color "[2] Herramientas de Eric Zimmerman" "White"
    Write-Color "[3] Herramientas de Nirsoft" "White"
    Write-Color "[4] Herramientas de Spokwn" "White"
    Write-Color "[5] Herramientas de Orbdiff" "White"
    Write-Color "[6] Otras herramientas útiles" "White"
    Write-Color "[7] Volver al menú principal" "White"
    Write-Host ""
    Write-Host "--------------------------------------------------------" -ForegroundColor Gray
    
    $choice = Read-Host "[?] Selecciona opción (1-7)"
    
    switch ($choice) {
        "1" {
            Invoke-DownloadAllTools
        }
        "2" {
            Invoke-DownloadZimmermanTools
        }
        "3" {
            Invoke-DownloadNirsoftTools
        }
        "4" {
            Invoke-DownloadSpokwnTools
        }
        "5" {
            Invoke-DownloadOrbdiffTools
        }
        "6" {
            Invoke-DownloadOtherTools
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
    
    Write-Color "Carpeta principal: $mainPath" "Cyan"
    Write-Host ""
    
   
    Invoke-DownloadZimmermanTools -silent $true
    Write-Host ""
    Invoke-DownloadNirsoftTools -silent $true
    Write-Host ""
    Invoke-DownloadSpokwnTools -silent $true
    Write-Host ""
    Invoke-DownloadOrbdiffTools -silent $true
    Write-Host ""
    Invoke-DownloadOtherTools -silent $true
    
    Write-Color "`n[+] ¡Todas las herramientas han sido descargadas!" "Green"
    Write-Color "[*] Ubicación: $mainPath" "Cyan"
    
    $open = Read-Host "`n[?] ¿Abrir carpeta principal? (S/N)"
    if ($open -match '^[SsYy]') {
        Start-Process $mainPath
    }
    
    Write-Host ""
    Write-Color "[*] Presiona Enter para continuar..." "White"
    $null = Read-Host
    Show-DownloadSSTools
}

function Invoke-DownloadZimmermanTools {
    param([bool]$silent = $false)
    
    if (-not $silent) {
        Clear-Host
        Write-Host ""
        Write-Color "[*] Descargando herramientas de Eric Zimmerman..." "Yellow"
    }
    
    $downloadPath = "C:\Screenshare\ZimmermanTools"
    if (!(Test-Path $downloadPath)) {
        New-Item -ItemType Directory -Path $downloadPath -Force | Out-Null
    }
    
    $tools = @(
        @{Name="AmcacheParser"; Url="https://download.ericzimmermanstools.com/net9/AmcacheParser.zip"},
        @{Name="AppCompatCacheParser"; Url="https://download.ericzimmermanstools.com/net9/AppCompatCacheParser.zip"},
        @{Name="RegistryExplorer"; Url="https://download.ericzimmermanstools.com/net9/RegistryExplorer.zip"},
        @{Name="MFTECmd"; Url="https://download.ericzimmermanstools.com/net9/MFTECmd.zip"},
        @{Name="PECmd"; Url="https://download.ericzimmermanstools.com/net9/PECmd.zip"}
    )
    
    $success = 0
    foreach ($tool in $tools) {
        if (-not $silent) {
            Write-Color "  $($tool.Name)..." "White" -NoNewline
        }
        try {
            $outputFile = "$downloadPath\$($tool.Name).zip"
            Invoke-WebRequest -Uri $tool.Url -OutFile $outputFile -UseBasicParsing | Out-Null
            if (-not $silent) {
                Write-Color " OK" "Green"
            }
            $success++
        }
        catch {
            if (-not $silent) {
                Write-Color " ERROR" "Red"
            }
        }
    }
    
    if (-not $silent) {
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
        Show-DownloadSSTools
    }
}

function Invoke-DownloadNirsoftTools {
    param([bool]$silent = $false)
    
    if (-not $silent) {
        Clear-Host
        Write-Host ""
        Write-Color "[*] Descargando herramientas de Nirsoft..." "Yellow"
    }
    
    $downloadPath = "C:\Screenshare\NirsoftTools"
    if (!(Test-Path $downloadPath)) {
        New-Item -ItemType Directory -Path $downloadPath -Force | Out-Null
    }
    
    $tools = @(
        @{Name="USBDeview"; Url="https://www.nirsoft.net/utils/usbdeview-x64.zip"},
        @{Name="NetworkUsageView"; Url="https://www.nirsoft.net/utils/networkusageview-x64.zip"},
        @{Name="AlternateStreamView"; Url="https://www.nirsoft.net/utils/alternatestreamview-x64.zip"},
        @{Name="WinPrefetchView"; Url="https://www.nirsoft.net/utils/winprefetchview-x64.zip"},
        @{Name="UninstallView"; Url="https://www.nirsoft.net/utils/uninstallview-x64.zip"}
    )
    
    $success = 0
    foreach ($tool in $tools) {
        if (-not $silent) {
            Write-Color "  $($tool.Name)..." "White" -NoNewline
        }
        try {
            $outputFile = "$downloadPath\$($tool.Name).zip"
            Invoke-WebRequest -Uri $tool.Url -OutFile $outputFile -UseBasicParsing | Out-Null
            
      
            Expand-Archive -Path $outputFile -DestinationPath $downloadPath -Force | Out-Null
            Remove-Item $outputFile -Force | Out-Null
            
            if (-not $silent) {
                Write-Color " OK" "Green"
            }
            $success++
        }
        catch {
            if (-not $silent) {
                Write-Color " ERROR" "Red"
            }
        }
    }
    
    if (-not $silent) {
        Write-Color "`n[+] $success/$($tools.Count) herramientas descargadas" "Green"
        Write-Color "[*] Ruta: $downloadPath" "Cyan"
        
        Write-Host ""
        Write-Color "[*] Presiona Enter para continuar..." "White"
        $null = Read-Host
        Show-DownloadSSTools
    }
}

function Invoke-DownloadSpokwnTools {
    param([bool]$silent = $false)
    
    if (-not $silent) {
        Clear-Host
        Write-Host ""
        Write-Color "[*] Descargando herramientas de Spokwn..." "Yellow"
    }
    
    $downloadPath = "C:\Screenshare\SpokwnTools"
    if (!(Test-Path $downloadPath)) {
        New-Item -ItemType Directory -Path $downloadPath -Force | Out-Null
    }
    
    $tools = @(
        @{Name="KernelLiveDumpTool"; Url="https://github.com/spokwn/KernelLiveDumpTool/releases/download/v1.1/KernelLiveDumpTool.exe"},
        @{Name="BAMParser"; Url="https://github.com/spokwn/BAM-parser/releases/download/v1.2.9/BAMParser.exe"},
        @{Name="PathsParser"; Url="https://github.com/spokwn/PathsParser/releases/download/v1.2/PathsParser.exe"},
        @{Name="PrefetchParser"; Url="https://github.com/spokwn/prefetch-parser/releases/download/v1.5.5/PrefetchParser.exe"},
        @{Name="ActivitiesCacheParser"; Url="https://github.com/spokwn/ActivitiesCache-execution/releases/download/v0.6.5/ActivitiesCacheParser.exe"}
    )
    
    $success = 0
    foreach ($tool in $tools) {
        if (-not $silent) {
            Write-Color "  $($tool.Name)..." "White" -NoNewline
        }
        try {
            $outputFile = "$downloadPath\$($tool.Name).exe"
            Invoke-WebRequest -Uri $tool.Url -OutFile $outputFile -UseBasicParsing | Out-Null
            if (-not $silent) {
                Write-Color " OK" "Green"
            }
            $success++
        }
        catch {
            if (-not $silent) {
                Write-Color " ERROR" "Red"
            }
        }
    }
    
    if (-not $silent) {
        Write-Color "`n[+] $success/$($tools.Count) herramientas descargadas" "Green"
        Write-Color "[*] Ruta: $downloadPath" "Cyan"
        
        Write-Host ""
        Write-Color "[*] Presiona Enter para continuar..." "White"
        $null = Read-Host
        Show-DownloadSSTools
    }
}

function Invoke-DownloadOrbdiffTools {
    param([bool]$silent = $false)
    
    if (-not $silent) {
        Clear-Host
        Write-Host ""
        Write-Color "[*] Descargando herramientas de Orbdiff..." "Yellow"
    }
    
    $downloadPath = "C:\Screenshare\OrbdiffTools"
    if (!(Test-Path $downloadPath)) {
        New-Item -ItemType Directory -Path $downloadPath -Force | Out-Null
    }
    
    $tools = @(
        @{Name="Fileless"; Url="https://github.com/Orbdiff/Fileless/releases/download/v1.1/Fileless.exe"},
        @{Name="JARParser"; Url="https://github.com/Orbdiff/JARParser/releases/download/v1.2/JARParser.exe"},
        @{Name="PFTrace"; Url="https://github.com/Orbdiff/PFTrace/releases/download/v1.0.1/PFTrace.exe"},
        @{Name="PrefetchView++"; Url="https://github.com/Orbdiff/PrefetchView/releases/download/v1.4/PrefetchView++.exe"}
    )
    
    $success = 0
    foreach ($tool in $tools) {
        if (-not $silent) {
            Write-Color "  $($tool.Name)..." "White" -NoNewline
        }
        try {
            $outputFile = "$downloadPath\$($tool.Name).exe"
            Invoke-WebRequest -Uri $tool.Url -OutFile $outputFile -UseBasicParsing | Out-Null
            if (-not $silent) {
                Write-Color " OK" "Green"
            }
            $success++
        }
        catch {
            if (-not $silent) {
                Write-Color " ERROR" "Red"
            }
        }
    }
    
    if (-not $silent) {
        Write-Color "`n[+] $success/$($tools.Count) herramientas descargadas" "Green"
        Write-Color "[*] Ruta: $downloadPath" "Cyan"
        
        Write-Host ""
        Write-Color "[*] Presiona Enter para continuar..." "White"
        $null = Read-Host
        Show-DownloadSSTools
    }
}

function Invoke-DownloadOtherTools {
    param([bool]$silent = $false)
    
    if (-not $silent) {
        Clear-Host
        Write-Host ""
        Write-Color "[*] Descargando otras herramientas útiles..." "Yellow"
    }
    
    $downloadPath = "C:\Screenshare\OtherTools"
    if (!(Test-Path $downloadPath)) {
        New-Item -ItemType Directory -Path $downloadPath -Force | Out-Null
    }
    
    $tools = @(
        @{Name="Everything"; Url="https://www.voidtools.com/Everything-1.4.1.1029.x86-Setup.exe"},
        @{Name="SystemInformer"; Url="https://github.com/winsiderss/si-builds/releases/download/3.2.25297.1516/systeminformer-build-canary-setup.exe"},
        @{Name="FTKImager"; Url="https://d1kpmuwb7gvu1i.cloudfront.net/AccessData_FTK_Imager_4.7.1.exe"},
        @{Name="Hayabusa"; Url="https://github.com/Yamato-Security/hayabusa/releases/download/v3.6.0/hayabusa-3.6.0-win-x64.zip"}
    )
    
    $success = 0
    foreach ($tool in $tools) {
        if (-not $silent) {
            Write-Color "  $($tool.Name)..." "White" -NoNewline
        }
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
            if (-not $silent) {
                Write-Color " OK" "Green"
            }
            $success++
        }
        catch {
            if (-not $silent) {
                Write-Color " ERROR" "Red"
            }
        }
    }
    
    if (-not $silent) {
        Write-Color "`n[+] $success/$($tools.Count) herramientas descargadas" "Green"
        Write-Color "[*] Ruta: $downloadPath" "Cyan"
        
        Write-Host ""
        Write-Color "[*] Presiona Enter para continuar..." "White"
        $null = Read-Host
        Show-DownloadSSTools
    }
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
    Write-Color "[2] 📥 Descargar SS Tools" "Cyan"
    Write-Color "[3] 🔍 Bam-Parser        " "Cyan"
    Write-Color "[4] ⚡ JarParser" "Cyan"
    Write-Color "[5] 🎯 Kill Screen Processes" "Cyan"
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
