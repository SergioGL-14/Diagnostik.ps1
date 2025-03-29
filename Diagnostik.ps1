# =========================================
# BLOQUE: Cargar librerías necesarias
# =========================================
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$global:RutaPsExec = "\\servidor\herramientas\PsExec.exe"

# =========================================
# Función auxiliar para determinar si el equipo es local
# =========================================
function Is-Local {
    param([string]$equipo)
    return ($equipo -eq $env:COMPUTERNAME -or $equipo -eq "localhost")
}

# =========================================
# BLOQUE: Crear formulario principal
# =========================================
$form = New-Object System.Windows.Forms.Form
$form.Text = "🛠️ Herramienta de Diagnóstico de Equipos"
$form.Size = New-Object System.Drawing.Size(1195, 720)
$form.MinimumSize = New-Object System.Drawing.Size(1000, 700)
$form.StartPosition = "CenterScreen"
$form.BackColor = [System.Drawing.Color]::FromArgb(245,245,245) # WhiteSmoke suave
$form.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$form.FormBorderStyle = "Sizable"
$form.AutoScaleMode = "Dpi"
$form.AutoScroll = $true

# =========================================
# BLOQUE: Panel izquierdo (Controles de análisis)
# =========================================
$panelIzquierdo = New-Object System.Windows.Forms.Panel
$panelIzquierdo.Size = New-Object System.Drawing.Size(360, 740)
$panelIzquierdo.Location = New-Object System.Drawing.Point(10,10)
$panelIzquierdo.BorderStyle = "None"
$panelIzquierdo.BackColor = [System.Drawing.Color]::FromArgb(230,230,230)  # Gris claro
$panelIzquierdo.Anchor = "Top,Bottom,Left"
$form.Controls.Add($panelIzquierdo)

# =========================================
# BLOQUE: Campo Nombre del Equipo
# =========================================
$lblEquipo = New-Object System.Windows.Forms.Label
$lblEquipo.Text = "Nombre del equipo:"
$lblEquipo.Location = New-Object System.Drawing.Point(10,15)
$lblEquipo.AutoSize = $true
$panelIzquierdo.Controls.Add($lblEquipo)

$txtEquipo = New-Object System.Windows.Forms.TextBox
$txtEquipo.Location = New-Object System.Drawing.Point(10,40)
$txtEquipo.Size = New-Object System.Drawing.Size(320,25)
$txtEquipo.Text = $env:COMPUTERNAME  # Por defecto, equipo actual
$panelIzquierdo.Controls.Add($txtEquipo)

# =========================================
# BLOQUE: Etiqueta de validación de equipo
# =========================================
$lblValidacionEquipo = New-Object System.Windows.Forms.Label
$lblValidacionEquipo.Location = New-Object System.Drawing.Point(10,68)
$lblValidacionEquipo.Size = New-Object System.Drawing.Size(320,20)
$lblValidacionEquipo.Text = ""
$lblValidacionEquipo.ForeColor = [System.Drawing.Color]::Gray
$panelIzquierdo.Controls.Add($lblValidacionEquipo)

function Validar-Equipo {
    param([string]$nombreEquipo)
    if (-not $nombreEquipo) {
        $lblValidacionEquipo.Text = ""
        return
    }
    if ($nombreEquipo -eq $env:COMPUTERNAME) {
        $lblValidacionEquipo.ForeColor = [System.Drawing.Color]::DarkGreen
        $lblValidacionEquipo.Text = "🔵 Equipo local"
    } else {
        $ping = Test-Connection -ComputerName $nombreEquipo -Count 1 -Quiet -ErrorAction SilentlyContinue
        if ($ping) {
            $lblValidacionEquipo.ForeColor = [System.Drawing.Color]::DarkBlue
            $lblValidacionEquipo.Text = "🌐 Remoto: responde al ping"
        } else {
            $lblValidacionEquipo.ForeColor = [System.Drawing.Color]::Red
            $lblValidacionEquipo.Text = "❌ Remoto: sin respuesta"
        }
    }
}

$txtEquipo.Add_TextChanged({
    $nombre = $txtEquipo.Text.Trim()
    Validar-Equipo -nombreEquipo $nombre
})

# =========================================
# BLOQUE: Árbol de selección de análisis
# =========================================
$treeAnalisis = New-Object System.Windows.Forms.TreeView
$treeAnalisis.Location = New-Object System.Drawing.Point(10,85)
$treeAnalisis.Size = New-Object System.Drawing.Size(320,480)
$treeAnalisis.CheckBoxes = $true
$treeAnalisis.HideSelection = $false
$panelIzquierdo.Controls.Add($treeAnalisis)

# Añadir nodos principales y subnodos
$nodoRed = $treeAnalisis.Nodes.Add("Diagnóstico de Red")
$nodoRed.Nodes.Add("Conectividad")
$nodoRed.Nodes.Add("DHCP")
$nodoRed.Nodes.Add("Adaptador de red")

$nodoRendimiento = $treeAnalisis.Nodes.Add("Rendimiento del Sistema")
$nodoRendimiento.Nodes.Add("Uso de CPU/RAM")
$nodoRendimiento.Nodes.Add("Procesos activos")
$nodoRendimiento.Nodes.Add("Espacio en disco")

$nodoEstabilidad = $treeAnalisis.Nodes.Add("Estabilidad del Sistema")
$nodoEstabilidad.Nodes.Add("Eventos críticos")
$nodoEstabilidad.Nodes.Add("Estado SMART")
$nodoEstabilidad.Nodes.Add("Drivers y reinicios")

$nodoDominio = $treeAnalisis.Nodes.Add("Dominio y AD")
$nodoDominio.Nodes.Add("Estado del dominio")
$nodoDominio.Nodes.Add("Controladores accesibles")
$nodoDominio.Nodes.Add("GPOs aplicadas")

$nodoDNS = $treeAnalisis.Nodes.Add("Diagnóstico de DNS")
$nodoDNS.Nodes.Add("Resolución directa/inversa")
$nodoDNS.Nodes.Add("DNS configurado")
$nodoDNS.Nodes.Add("Estado del servicio DNS")

$nodoServicios = $treeAnalisis.Nodes.Add("Servicios del Sistema")
$nodoServicios.Nodes.Add("WinRM, WMI, BITS")
$nodoServicios.Nodes.Add("Errores de servicio")
$nodoServicios.Nodes.Add("Actualizaciones recientes")

$nodoArchivos = $treeAnalisis.Nodes.Add("Sistema de Archivos")
$nodoArchivos.Nodes.Add("SFC /scannow")
$nodoArchivos.Nodes.Add("CHKDSK")
$nodoArchivos.Nodes.Add("DISM /Online /Cleanup-Image")

$nodoArranque = $treeAnalisis.Nodes.Add("Arranque y Rendimiento")
$nodoArranque.Nodes.Add("Tiempos de arranque")
$nodoArranque.Nodes.Add("Servicios lentos")

$nodoInicio = $treeAnalisis.Nodes.Add("Inicio automático")
$nodoInicio.Nodes.Add("Apps al iniciar")
$nodoInicio.Nodes.Add("Tareas programadas")

$nodoEventos = $treeAnalisis.Nodes.Add("Visor de Eventos Avanzado")
$nodoEventos.Nodes.Add("Red")
$nodoEventos.Nodes.Add("Sistema")
$nodoEventos.Nodes.Add("Seguridad")
$nodoEventos.Nodes.Add("Aplicacións")

$nodoPostHang = $treeAnalisis.Nodes.Add("Diagnóstico Post-cuelgue")
$nodoPostHang.Nodes.Add("Winlogon / Perfil de Usuario")
$nodoPostHang.Nodes.Add("Lock/Unlock + Logon")
$nodoPostHang.Nodes.Add("Análisis .WER")
$nodoPostHang.Nodes.Add("Reliability Monitor")

$nodoRapidos = $treeAnalisis.Nodes.Add("Análisis Rápidos")
$nodoRapidos.Nodes.Add("Análisis de red")
$nodoRapidos.Nodes.Add("Análisis de rendimiento")
$nodoRapidos.Nodes.Add("Análisis de problemas")
$nodoRapidos.Nodes.Add("Diagnostico-PostHang")

# =========================================
# BLOQUE: Evento AfterCheck en el TreeView
# =========================================
$treeAnalisis.add_AfterCheck({
    param($sender, $e)
    if ($e.Action -eq [System.Windows.Forms.TreeViewAction]::Unknown) { return }
    if ($e.Node.Nodes.Count -gt 0) {
        foreach ($child in $e.Node.Nodes) {
            $child.Checked = $e.Node.Checked
        }
    }
    if ($e.Node -and $e.Node.Parent) {
        $todosMarcados = $true
        foreach ($sibling in $e.Node.Parent.Nodes) {
            if (-not $sibling.Checked) { $todosMarcados = $false; break }
        }
        $e.Node.Parent.Checked = $todosMarcados
    }
})

# =========================================
# BLOQUE: Botón de Análisis
# =========================================
$btnAnalizar = New-Object System.Windows.Forms.Button
$btnAnalizar.Text = "🧪 Analizar"
$btnAnalizar.Size = New-Object System.Drawing.Size(320,40)
$btnAnalizar.Location = New-Object System.Drawing.Point(10,580)
$btnAnalizar.BackColor = [System.Drawing.Color]::FromArgb(30,144,255)  # DodgerBlue
$btnAnalizar.ForeColor = [System.Drawing.Color]::White
$btnAnalizar.FlatStyle = "Flat"
$btnAnalizar.Font = New-Object System.Drawing.Font("Segoe UI Emoji",10)
$panelIzquierdo.Controls.Add($btnAnalizar)

# =========================================
# BLOQUE: Panel derecho (Log de resultados)
# =========================================
$panelDerecho = New-Object System.Windows.Forms.Panel
$panelDerecho.Size = New-Object System.Drawing.Size(800,660)
$panelDerecho.Location = New-Object System.Drawing.Point(370,10)
$panelDerecho.BorderStyle = "FixedSingle"
$form.Controls.Add($panelDerecho)

$txtLog = New-Object System.Windows.Forms.RichTextBox
$txtLog.Multiline = $true
$txtLog.ReadOnly = $true
$txtLog.Dock = "Fill"
$txtLog.BackColor = "White"
$txtLog.ScrollBars = "Vertical"
$txtLog.Font = New-Object System.Drawing.Font("Segoe UI Emoji",10)
$panelDerecho.Controls.Add($txtLog)

# =========================================
# BLOQUE: Funciones para escribir en el log
# =========================================
function Escribir-Log {
    param(
        [string]$Texto,
        [switch]$Separador
    )
    if ($Separador) {
        Invoke-SafeLog -Texto ("`n" + ("=" * 80) + "`n")
    }
    Invoke-SafeLog -Texto "$Texto"
}

function Invoke-SafeLog {
    param(
        [string]$Texto,
        [System.Drawing.Color]$Color = [System.Drawing.Color]::Black,
        [string]$Category = "",
        [string]$Level = ""
    )
    if ($txtLog.InvokeRequired) {
        $txtLog.Invoke([Action]{
            $txtLog.SelectionColor = $Color
            $txtLog.AppendText("$Texto`n")
            $txtLog.ScrollToCaret()
        })
    } else {
        $txtLog.SelectionColor = $Color
        $txtLog.AppendText("$Texto`n")
        $txtLog.ScrollToCaret()
    }
}

function Wait-ForFile {
    param(
        [string]$FilePath,
        [int]$TimeoutSeconds = 10
    )
    $elapsed = 0
    while (-not (Test-Path $FilePath) -and ($elapsed -lt $TimeoutSeconds)) {
        Start-Sleep -Seconds 1
        $elapsed++
    }
    return (Test-Path $FilePath)
}

# =========================================
# BLOQUE: Funciones de Diagnóstico
# =========================================

# --- Diagnostico-Conectividad ---
function Diagnostico-Conectividad {
    param([string]$equipo)
    try {
        if (Is-Local $equipo) {
            $netConfig = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
        } else {
            $netConfig = Get-CimInstance Win32_NetworkAdapterConfiguration -ComputerName $equipo | Where-Object { $_.IPEnabled -eq $true }
        }
        if (-not $netConfig) {
            Escribir-Log -Texto "❌ No se pudo obtener configuración de red para el equipo."
            return
        }
        if ($netConfig.IPAddress.Count -gt 1) {
            Escribir-Log -Texto "⚠️ Múltiples IP detectadas. Usando la primera: $($netConfig.IPAddress[0])"
            $ip = $netConfig.IPAddress[0]
        } else {
            $ip = $netConfig.IPAddress[0]
        }
        $mac = $netConfig.MACAddress
        $dns = $netConfig.DNSServerSearchOrder -join ", "
        $gateway = $netConfig.DefaultIPGateway[0]
        Escribir-Log -Texto "🔎 IP: $ip"
        Escribir-Log -Texto "🔎 MAC: $mac"
        Escribir-Log -Texto "🔎 Puerta de enlace: $gateway"
        Escribir-Log -Texto "🔎 DNS: $dns"
        if ($gateway) {
            Escribir-Log -Texto "`n⏱️ Ping a Gateway ($gateway)..."
            $ping1 = Test-Connection -ComputerName $gateway -Count 2 -Quiet -ErrorAction SilentlyContinue
            if ($ping1) { Escribir-Log -Texto "✅ Gateway responde." }
            else { Escribir-Log -Texto "❌ Sin respuesta de la puerta de enlace." }
        } else {
            Escribir-Log -Texto "⚠️ No se detectó puerta de enlace."
        }
        Escribir-Log -Texto "`n⏱️ Ping a DNS Google (8.8.8.8)..."
        $ping2 = Test-Connection -ComputerName "8.8.8.8" -Count 2 -Quiet -ErrorAction SilentlyContinue
        if ($ping2) { Escribir-Log -Texto "✅ Conexión externa OK (8.8.8.8)." }
        else { Escribir-Log -Texto "❌ Sin respuesta desde 8.8.8.8." }
    } catch {
        Escribir-Log -Texto "❌ Error en conectividad: $_"
    }
}

# --- Diagnostico-DHCP ---
function Diagnostico-DHCP {
    param([string]$equipo)
    try {
        if (Is-Local $equipo) {
            $netConfig = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
        } else {
            $netConfig = Get-CimInstance Win32_NetworkAdapterConfiguration -ComputerName $equipo | Where-Object { $_.IPEnabled -eq $true }
        }
        if (-not $netConfig) {
            Escribir-Log -Texto "❌ No se encontró configuración de red."
            return
        }
        $dhcpHabilitado = if ($netConfig.DHCPEnabled) { "Sí" } else { "No" }
        $ip = $netConfig.IPAddress[0]
        $tipoIP = if ($ip.StartsWith("169.")) { "Autoconfigurada (sin DHCP)" } else { "Válida" }
        Escribir-Log -Texto "🔎 DHCP: $dhcpHabilitado"
        Escribir-Log -Texto "🔎 IP: $ip ($tipoIP)"
        if (Is-Local $equipo) {
            $servicio = Get-CimInstance Win32_Service | Where-Object { $_.Name -eq 'Dhcp' }
        } else {
            $servicio = Get-CimInstance Win32_Service -ComputerName $equipo -Filter "Name='Dhcp'" -ErrorAction SilentlyContinue
        }
        if ($servicio) {
            Escribir-Log -Texto "🔧 DHCP Client: $($servicio.Status) (Inicio: $($servicio.StartType))"
        } else {
            Escribir-Log -Texto "❌ No se pudo consultar el servicio DHCP Client."
        }
        if (Is-Local $equipo) {
            Escribir-Log -Texto "`n♻️ Renovando IP con ipconfig /renew..."
            try {
                $resultado = ipconfig /renew 2>&1
                if ($resultado -match "Error") { Escribir-Log -Texto "❌ Error al renovar IP: $resultado" }
                else { Escribir-Log -Texto "✅ Renovación completada." }
            } catch {
                Escribir-Log -Texto "⚠️ Error durante renovación: $_"
            }
        } else {
            Escribir-Log -Texto "`nℹ️ Renovación IP no disponible para remotos."
        }
    } catch {
        Escribir-Log -Texto "❌ Error en DHCP: $_"
    }
}

# --- Diagnostico-AdaptadorRed ---
function Diagnostico-AdaptadorRed {
    param([string]$equipo)
    $NombreFuncion = "AdaptadorRed"
    Invoke-SafeLog "[🔎] Diagnóstico de adaptadores de red..." -Category $NombreFuncion
    $session = $null
    try {
        if (Is-Local $equipo) {
            $adaptadores = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled = TRUE"
        } else {
            $session = New-CimSession -ComputerName $equipo -ErrorAction Stop
            $adaptadores = Get-CimInstance -CimSession $session -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled = TRUE"
        }
        if (-not $adaptadores) {
            Invoke-SafeLog "❌ No se detectaron adaptadores con IP habilitada." -Category $NombreFuncion
            return
        }
        foreach ($a in $adaptadores) {
            try {
                $ip = ($a.IPAddress) -join ", "
                $dns = ($a.DNSServerSearchOrder) -join ", "
                $dhcp = if ($a.DHCPEnabled) { "Sí" } else { "No" }
                $descripcion = $a.Description
                $mensaje = "📡 Adaptador: $descripcion | IP: $ip | DHCP: $dhcp | DNS: $dns"
                Invoke-SafeLog $mensaje -Category $NombreFuncion
                if ($a.IPEnabled -and -not $a.DHCPEnabled) {
                    Invoke-SafeLog "⚠️ DHCP deshabilitado en $descripcion" -Category $NombreFuncion -Level Warning
                }
            } catch {
                Invoke-SafeLog "⚠️ Error procesando adaptador: $_" -Category $NombreFuncion -Level Warning
            }
        }
        Invoke-SafeLog "[✔️] Análisis de adaptadores completado." -Category $NombreFuncion
    } catch {
        Invoke-SafeLog "⚠️ Error en adaptadores: $($_.Exception.Message)" -Category $NombreFuncion -Level Warning
    } finally {
        if ($session) { $session | Remove-CimSession }
    }
}

# --- Diagnostico-Rendimiento ---
function Diagnostico-Rendimiento {
    param([string]$equipo)
    try {
        Escribir-Log -Texto "📈 Análisis de rendimiento en $equipo..."
        $esRemoto = -not (Is-Local $equipo)
        $archivoLocal = "$env:TEMP\rendimiento_$equipo.txt"
        if ($esRemoto) {
            New-Item -Path "\\$equipo\C$\Temp" -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
            $archivoRemoto = "\\$equipo\C$\Temp\rendimiento_diagnostico.txt"
            if (-not (Test-Path $global:RutaPsExec)) {
                Invoke-SafeLog -Texto "❌ PsExec no encontrado: $global:RutaPsExec" -Color ([System.Drawing.Color]::Red)
                return
            }
            $scriptRemoto = @'
@echo off
setlocal enabledelayedexpansion
set OUTPUT=C:\Temp\rendimiento_diagnostico.txt
echo ==== USO DE CPU Y MEMORIA ==== > !OUTPUT!
for /f "tokens=2 delims==." %%i in ('"wmic cpu get loadpercentage /value"') do echo CPU %%i%% >> !OUTPUT!
for /f "tokens=2 delims==" %%i in ('"wmic OS get FreePhysicalMemory /value"') do set MEMFREE=%%i
for /f "tokens=2 delims==" %%i in ('"wmic OS get TotalVisibleMemorySize /value"') do set MEMTOTAL=%%i
set /a MEMUSED=!MEMTOTAL! - !MEMFREE!
set /a PERCENT=(!MEMUSED!*100)/!MEMTOTAL!
echo RAM: !MEMUSED! KB usados de !MEMTOTAL! KB (!PERCENT!%%) >> !OUTPUT!
echo. >> !OUTPUT!
echo ==== TOP 5 PROCESOS POR RAM ==== >> !OUTPUT!
wmic process get name,workingsetsize | sort /R /+2 | more +1 | findstr /R "[0-9]" | sort /R /+2 | more +1 >> !OUTPUT!
echo ==== TOP 5 PROCESOS POR CPU ==== >> !OUTPUT!
wmic path Win32_PerfFormattedData_PerfProc_Process get Name,PercentProcessorTime | sort /R +1 | more +1 | findstr /R "[0-9]" | sort /R +1 | more +1 | for /L %%a in (1,1,5) do @echo. >> !OUTPUT!
'@
            $scriptPath = "$env:TEMP\remote_perf_script.cmd"
            $scriptRemoto | Set-Content -Path $scriptPath -Encoding ASCII
            Copy-Item -Path $scriptPath -Destination "\\$equipo\C$\Temp\perf_diag.cmd" -Force -ErrorAction SilentlyContinue
            Start-Process -FilePath $global:RutaPsExec -ArgumentList "\\$equipo -s -accepteula cmd /c C:\Temp\perf_diag.cmd" -Wait -WindowStyle Hidden
            if (Wait-ForFile -FilePath $archivoRemoto -TimeoutSeconds 10) {
                Copy-Item -Path $archivoRemoto -Destination $archivoLocal -Force -ErrorAction SilentlyContinue
                Remove-Item $archivoRemoto -Force -ErrorAction SilentlyContinue
            } else {
                Escribir-Log -Texto "❌ Archivo remoto de rendimiento no generado en tiempo."
                return
            }
        } else {
            try {
                $cpuInfo = Get-CimInstance -ClassName Win32_Processor
                $cpuPorcentaje = [math]::Round($cpuInfo.LoadPercentage, 1)
                $compInfo = Get-CimInstance -ClassName Win32_OperatingSystem
                $memTotal = [math]::Round($compInfo.TotalVisibleMemorySize / 1MB, 1)
                $memLibre = [math]::Round($compInfo.FreePhysicalMemory / 1MB, 1)
                $memUsada = [math]::Round($memTotal - $memLibre, 1)
                $memPorcentaje = [math]::Round(($memUsada / $memTotal) * 100, 1)
                Escribir-Log -Texto "🧠 CPU: $cpuPorcentaje %"
                Escribir-Log -Texto "💾 RAM: $memUsada GB de $memTotal GB ($memPorcentaje%)"
                return
            } catch {
                Escribir-Log -Texto "⚠️ Error local en rendimiento: $_"
                return
            }
        }
        if (Test-Path $archivoLocal) {
            Escribir-Log -Texto "`n📋 Resultado del rendimiento:`n"
            Get-Content $archivoLocal | ForEach-Object { Escribir-Log -Texto $_ }
            Remove-Item $archivoLocal -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Escribir-Log -Texto "❌ Error en rendimiento: $_"
    }
}

# --- Diagnostico-ProcesosActivos ---
function Diagnostico-ProcesosActivos {
    param([string]$equipo)
    try {
        Escribir-Log -Texto "📋 Procesos activos en $equipo (ordenados por uso de RAM):`n"
        $esLocal = Is-Local $equipo
        if ($esLocal) {
            $procesos = Get-Process | Sort-Object WorkingSet -Descending
        } else {
            $procesos = Get-CimInstance Win32_Process -ComputerName $equipo -ErrorAction Stop | Sort-Object WorkingSetSize -Descending
        }
        $total = 0
        foreach ($proc in $procesos) {
            try {
                if ($esLocal) {
                    $ramMB = [math]::Round($proc.WorkingSet / 1MB, 1)
                    $nombre = $proc.ProcessName
                    $procID = $proc.Id
                } else {
                    $ramMB = [math]::Round($proc.WorkingSetSize / 1MB, 1)
                    $nombre = $proc.Name
                    $procID = $proc.ProcessId
                }
                $sospechoso = $false
                $listaNegra = @("MsMpEng", "Teams", "java", "chrome", "powershell", "wmiprvse", "svchost")
                if ($listaNegra -contains $nombre -or $ramMB -gt 500) {
                    $sospechoso = $true
                }
                $linea = (" - {0,-25} PID: {1,-6} RAM: {2,6} MB" -f $nombre, $procID, $ramMB)
                if ($sospechoso) {
                    $txtLog.SelectionColor = [System.Drawing.Color]::Red
                } else {
                    $txtLog.SelectionColor = [System.Drawing.Color]::Black
                }
                $txtLog.AppendText($linea + "`n")
                $total++
            } catch {
                Invoke-SafeLog "⚠️ Error procesando el proceso $($proc.Name): $_" -Level Warning
            }
        }
        $txtLog.SelectionColor = [System.Drawing.Color]::Black
        Escribir-Log -Texto "`nTotal de procesos activos: $total"
    } catch {
        Escribir-Log -Texto "❌ Error en procesos activos: $_"
    }
}

# --- Diagnostico-EspacioDisco ---
function Diagnostico-EspacioDisco {
    param([string]$equipo)
    try {
        Escribir-Log -Texto "💽 Espacio en disco de $equipo`n"
        if (Is-Local $equipo) {
            $discos = Get-CimInstance -Class Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction Stop
        } else {
            $discos = Get-CimInstance -Class Win32_LogicalDisk -ComputerName $equipo -Filter "DriveType=3" -ErrorAction Stop
        }
        if (-not $discos) {
            Escribir-Log -Texto "❌ No se encontraron discos."
            return
        }
        foreach ($d in $discos) {
            try {
                $unidad = $d.DeviceID
                $totalGB = [math]::Round($d.Size / 1GB, 1)
                $libreGB = [math]::Round($d.FreeSpace / 1GB, 1)
                $porcentajeLibre = [math]::Round(($libreGB / $totalGB) * 100, 1)
                $linea = " - Unidad $unidad $libreGB GB libres de $totalGB GB ($porcentajeLibre% libre)"
                if ($porcentajeLibre -lt 15) {
                    $txtLog.SelectionColor = [System.Drawing.Color]::Red
                } else {
                    $txtLog.SelectionColor = [System.Drawing.Color]::Black
                }
                $txtLog.AppendText("$linea`n")
            } catch {
                Invoke-SafeLog "⚠️ Error procesando disco: $_" -Level Warning
            }
        }
        $txtLog.SelectionColor = [System.Drawing.Color]::Black
    } catch {
        Escribir-Log -Texto "❌ Error en espacio en disco: $_"
    }
}

# --- Diagnostico-EventosCriticos ---
function Diagnostico-EventosCriticos {
    param([string]$equipo)
    try {
        Escribir-Log -Texto "📑 Buscando eventos críticos en $equipo`n"
        $idsCriticos = @(41, 6008)
        $fuentesCriticas = @("Microsoft-Windows-Kernel-Power", "EventLog", "BugCheck")
        $eventos = Get-WinEvent -ComputerName $equipo -LogName System -MaxEvents 100 -ErrorAction SilentlyContinue |
                   Where-Object { $_.Id -in $idsCriticos -or $_.ProviderName -in $fuentesCriticas }
        if (-not $eventos -or $eventos.Count -eq 0) {
            Escribir-Log -Texto "✅ No se encontraron eventos críticos."
            return
        }
        foreach ($evento in $eventos) {
            try {
                $fecha = $evento.TimeCreated
                $fuente = $evento.ProviderName
                $id = $evento.Id
                $mensaje = $evento.Message -replace "`r`n", " " -replace "\s+", " "
                $resumen = $mensaje.Substring(0, [Math]::Min(100, $mensaje.Length)) + "..."
                $txtLog.SelectionColor = [System.Drawing.Color]::Red
                $txtLog.AppendText("⚠️ [$fecha] [$fuente] Evento $id`n")
                $txtLog.SelectionColor = [System.Drawing.Color]::Black
                $txtLog.AppendText("   📄 $resumen`n`n")
            } catch {
                Invoke-SafeLog "⚠️ Error procesando un evento: $_" -Level Warning
            }
        }
    } catch {
        Escribir-Log -Texto "❌ Error en eventos críticos: $_"
    }
}

# --- Diagnostico-DiscoSMART ---
function Diagnostico-DiscoSMART {
    param([string]$equipo)
    try {
        Escribir-Log -Texto "🔍 Comprobando SMART del disco en $equipo`n"
        $esRemoto = -not (Is-Local $equipo)
        $archivoLocal = "$env:TEMP\smart_result_$equipo.txt"
        $archivoRemoto = "\\$equipo\C$\Temp\smart_result.txt"
        if ($esRemoto) {
            New-Item -Path "\\$equipo\C$\Temp" -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
            if (-not (Test-Path $global:RutaPsExec)) {
                Invoke-SafeLog -Texto "❌ PsExec no encontrado: $global:RutaPsExec" -Color ([System.Drawing.Color]::Red)
                return
            }
            $cmd = 'wmic /namespace:"\\root\wmi" path MSStorageDriver_FailurePredictStatus get PredictFailure > C:\Temp\smart_result.txt'
            Start-Process -FilePath $global:RutaPsExec -ArgumentList "\\$equipo -s -accepteula cmd /c $cmd" -Wait -WindowStyle Hidden
            if (Wait-ForFile -FilePath $archivoRemoto -TimeoutSeconds 10) {
                Copy-Item -Path $archivoRemoto -Destination $archivoLocal -Force -ErrorAction SilentlyContinue
                Remove-Item $archivoRemoto -Force -ErrorAction SilentlyContinue
            } else {
                Escribir-Log -Texto "❌ SMART: archivo remoto no generado."
                return
            }
        } else {
            $archivoLocal = "$env:TEMP\smart_result_local.txt"
            $cmd = 'wmic /namespace:"\\root\wmi" path MSStorageDriver_FailurePredictStatus get PredictFailure > "' + $archivoLocal + '"'
            Start-Process -FilePath "cmd.exe" -ArgumentList "/c $cmd" -Wait -WindowStyle Hidden
        }
        if (-not (Test-Path $archivoLocal)) {
            Escribir-Log -Texto "❌ SMART: No se pudo leer el resultado."
            return
        }
        $contenido = Get-Content $archivoLocal | Where-Object { $_.Trim() -match "^(0|1)$" }
        Remove-Item $archivoLocal -Force -ErrorAction SilentlyContinue
        if (-not $contenido -or $contenido.Count -eq 0) {
            Escribir-Log -Texto "⚠️ SMART: Sin datos."
            return
        }
        $valor = $contenido[0].Trim()
        if ($valor -eq "0") {
            Invoke-SafeLog -Texto "✅ SMART: Sin fallos (PredictFailure = 0)." -Color ([System.Drawing.Color]::DarkGreen)
        } elseif ($valor -eq "1") {
            Invoke-SafeLog -Texto "❌ SMART: Fallos físicos inminentes (PredictFailure = 1)." -Color ([System.Drawing.Color]::Red)
        } else {
            Escribir-Log -Texto "⚠️ SMART: Resultado inesperado: $valor"
        }
    } catch {
        Escribir-Log -Texto "❌ Error en SMART: $_"
    }
}

# --- Diagnostico-DriversYReinicios ---
function Diagnostico-DriversYReinicios {
    param([string]$equipo)
    try {
        Escribir-Log -Texto "📦 Analizando drivers en $equipo`n"
        $esRemoto = -not (Is-Local $equipo)
        $hoy = Get-Date
        $driverProblemas = 0
        if (Is-Local $equipo) {
            $drivers = Get-CimInstance -Class Win32_PnPSignedDriver -ErrorAction SilentlyContinue | Sort-Object DriverDate -Descending
        } else {
            $drivers = Get-CimInstance -Class Win32_PnPSignedDriver -ComputerName $equipo -ErrorAction SilentlyContinue | Sort-Object DriverDate -Descending
        }
        if (-not $drivers) {
            Invoke-SafeLog -Texto "❌ No se pudieron obtener los drivers." -Color ([System.Drawing.Color]::Red)
            return
        }
        foreach ($d in $drivers) {
            try {
                $nombre = $d.DeviceName
                $proveedor = $d.DriverProviderName
                $fechaTexto = $d.DriverDate
                $fecha = $null
                if ($fechaTexto -match '^\d{8}') {
                    $fecha = [datetime]::ParseExact($fechaTexto.Substring(0,8), 'yyyyMMdd', $null)
                }
                $estado = $d.Status
                $version = $d.DriverVersion
                $antiguo = $false
                if ($fecha -is [datetime]) {
                    $antiguo = (($hoy.Year - $fecha.Year) -gt 5)
                }
                $conError = $estado -ne "OK"
                if ($antiguo -or $conError) {
                    $txtLog.SelectionColor = [System.Drawing.Color]::Red
                    $driverProblemas++
                } else {
                    $txtLog.SelectionColor = [System.Drawing.Color]::Black
                }
                $fechaTextoFinal = if ($fecha -is [datetime]) { $fecha.ToShortDateString() } else { $fecha }
                $txtLog.AppendText(" - $nombre → Versión: $version, Fecha: $fechaTextoFinal, Estado: $estado`n")
            } catch {
                Invoke-SafeLog "⚠️ Error procesando driver: $($_.Exception.Message)" -Level Warning
            }
        }
        $txtLog.SelectionColor = [System.Drawing.Color]::Black
        Escribir-Log -Texto "`n⚠️ Drivers con problemas: $driverProblemas"
        Escribir-Log -Texto "`n🔄 Analizando eventos de reinicio..."
        $archivoRemoto = "\\$equipo\C$\Temp\reinicios_result.txt"
        $archivoLocal = "$env:TEMP\reinicios_result_$equipo.txt"
        if ($esRemoto) {
            if (-not (Test-Path $global:RutaPsExec)) {
                Escribir-Log -Texto "❌ PsExec no encontrado: $global:RutaPsExec"
                return
            }
            $cmd = 'cmd.exe /c nltest /dsgetdc:'  # (este comando se usó en otro bloque; aquí se usa wevtutil)
            $cmd = 'wevtutil qe System /q:"*[System[(EventID=41 or EventID=6008 or EventID=1074 or EventID=1076)]]" /f:text /c:10 > C:\Temp\reinicios_result.txt'
            Start-Process -FilePath $global:RutaPsExec -ArgumentList "\\$equipo -s -accepteula cmd /c $cmd" -Wait -WindowStyle Hidden
            Start-Sleep -Seconds 3
            if (Test-Path $archivoRemoto) {
                Copy-Item -Path $archivoRemoto -Destination $archivoLocal -Force -ErrorAction SilentlyContinue
                Remove-Item $archivoRemoto -Force -ErrorAction SilentlyContinue
            } else {
                Escribir-Log -Texto "❌ No se encontró archivo de reinicios en remoto."
                return
            }
        } else {
            $cmd = 'wevtutil qe System /q:"*[System[(EventID=41 or EventID=6008 or EventID=1074 or EventID=1076)]]" /f:text /c:10 > "' + $archivoLocal + '"'
            Start-Process -FilePath "cmd.exe" -ArgumentList "/c $cmd" -Wait -WindowStyle Hidden
        }
        if (-not (Test-Path $archivoLocal)) {
            Escribir-Log -Texto "❌ No se pudo leer archivo de reinicios."
            return
        }
        $lineas = Get-Content $archivoLocal
        Remove-Item $archivoLocal -Force -ErrorAction SilentlyContinue
        $resumenActual = ""
        foreach ($linea in $lineas) {
            if ($linea -match "TimeCreated") {
                if ($resumenActual) {
                    $txtLog.SelectionColor = [System.Drawing.Color]::Red
                    $txtLog.AppendText("⚠️ $resumenActual`n")
                }
                $resumenActual = "$linea"
            } else {
                $resumenActual += " | $linea"
            }
        }
        if ($resumenActual) {
            $txtLog.SelectionColor = [System.Drawing.Color]::Red
            $txtLog.AppendText("⚠️ $resumenActual`n")
        }
        $txtLog.SelectionColor = [System.Drawing.Color]::Black
    } catch {
        Escribir-Log -Texto "❌ Error en drivers/reinicios: $_"
    }
}

# --- Diagnostico-EstadoDominio ---
function Diagnostico-EstadoDominio {
    param([string]$equipo)
    try {
        Escribir-Log -Texto "🏢 Consultando dominio en $equipo`n"
        if (Is-Local $equipo) {
            $comp = Get-CimInstance -Class Win32_ComputerSystem -ErrorAction SilentlyContinue
        } else {
            $comp = Get-CimInstance -Class Win32_ComputerSystem -ComputerName $equipo -ErrorAction SilentlyContinue
        }
        if (-not $comp) {
            Invoke-SafeLog -Texto "❌ No se pudo obtener información del equipo." -Color ([System.Drawing.Color]::Red)
            return
        }
        $nombreEquipo = $comp.Name
        $dominio = $comp.Domain
        $esDominio = $comp.PartOfDomain
        if ($esDominio) {
            Escribir-Log -Texto "✅ Pertenece al dominio: $dominio"
        } else {
            $txtLog.SelectionColor = [System.Drawing.Color]::Red
            $txtLog.AppendText("❌ El equipo NO está unido a un dominio.`n")
            $txtLog.SelectionColor = [System.Drawing.Color]::Black
            return
        }
        try {
            if (Is-Local $equipo) {
                $usuarios = Get-CimInstance Win32_UserAccount -ErrorAction SilentlyContinue | Where-Object { $_.Domain -eq $dominio }
            } else {
                $usuarios = Get-CimInstance Win32_UserAccount -ComputerName $equipo -Filter "Domain='$dominio'" -ErrorAction SilentlyContinue
            }
            $usuarioActual = $usuarios | Where-Object { $_.Name -eq $env:USERNAME }
            if ($usuarioActual) {
                $sid = $usuarioActual.SID
                Escribir-Log -Texto "🔐 SID: $sid"
            } else {
                Escribir-Log -Texto "⚠️ No se pudo obtener SID del usuario."
            }
        } catch {
            Escribir-Log -Texto "⚠️ Error recuperando SID: $_"
        }
        Escribir-Log -Texto "🖥️ Equipo: $nombreEquipo"
        $archivoPDC = "\\$equipo\C$\Temp\pdc.txt"
        $archivoLocal = "$env:TEMP\pdc_$equipo.txt"
        if (-not (Is-Local $equipo)) {
            if (-not (Test-Path $global:RutaPsExec)) {
                Escribir-Log -Texto "❌ PsExec no encontrado: $global:RutaPsExec"
                return
            }
            Escribir-Log -Texto "🌐 Consultando PDC remoto..."
            $cmd = 'cmd.exe /c nltest /dsgetdc:' + $dominio + ' > C:\Temp\pdc.txt'
            Start-Process -FilePath $global:RutaPsExec -ArgumentList "\\$equipo -s -accepteula $cmd" -Wait -WindowStyle Hidden
            Start-Sleep -Seconds 3
            if (Test-Path $archivoPDC) {
                Copy-Item -Path $archivoPDC -Destination $archivoLocal -Force -ErrorAction SilentlyContinue
                Remove-Item $archivoPDC -Force -ErrorAction SilentlyContinue
            } else {
                Escribir-Log -Texto "⚠️ PDC remoto no obtenido."
                return
            }
        } else {
            $cmd = "nltest /dsgetdc:$dominio > `"$archivoLocal`""
            Start-Process -FilePath "cmd.exe" -ArgumentList "/c $cmd" -Wait -WindowStyle Hidden
        }
        if (-not (Test-Path $archivoLocal)) {
            Escribir-Log -Texto "❌ No se pudo leer el resultado del PDC."
            return
        }
        $pdcContenido = Get-Content $archivoLocal
        Remove-Item $archivoLocal -Force -ErrorAction SilentlyContinue
        $pdcLinea = $pdcContenido | Where-Object { $_ -match "Domain Controller Name" }
        if ($pdcLinea) {
            $pdcNombre = $pdcLinea -replace ".*:\\s+", ""
            Escribir-Log -Texto "📡 PDC: $pdcNombre"
            $ping = Test-Connection -ComputerName $pdcNombre -Count 1 -Quiet -ErrorAction SilentlyContinue
            if ($ping) { Escribir-Log -Texto "✅ PDC responde." }
            else {
                $txtLog.SelectionColor = [System.Drawing.Color]::Red
                $txtLog.AppendText("⚠️ PDC no responde.`n")
                $txtLog.SelectionColor = [System.Drawing.Color]::Black
            }
        } else {
            Escribir-Log -Texto "⚠️ No se extrajo nombre del PDC."
        }
    } catch {
        Escribir-Log -Texto "❌ Error en estado de dominio: $_"
    }
}

# --- Diagnostico-ControladoresDominio ---
function Diagnostico-ControladoresDominio {
    param([string]$equipo)
    try {
        Escribir-Log -Texto "🔍 Buscando controladores de dominio en $equipo`n"
        if (Is-Local $equipo) {
            $comp = Get-CimInstance -Class Win32_ComputerSystem -ErrorAction SilentlyContinue
        } else {
            $comp = Get-CimInstance -Class Win32_ComputerSystem -ComputerName $equipo -ErrorAction SilentlyContinue
        }
        $dominio = $comp.Domain
        if (-not $dominio) {
            Invoke-SafeLog -Texto "❌ No se pudo determinar el dominio." -Color ([System.Drawing.Color]::Red)
            return
        }
        if (-not (Is-Local $equipo)) {
            if (-not (Test-Path $global:RutaPsExec)) {
                Escribir-Log -Texto "❌ PsExec no encontrado: $global:RutaPsExec"
                return
            }
            $archivoRemoto = "\\$equipo\C$\Temp\dclist.txt"
            $archivoLocal = "$env:TEMP\dclist_$equipo.txt"
            $cmd = "cmd.exe /c nltest /dclist:$dominio > C:\Temp\dclist.txt"
            Start-Process -FilePath $global:RutaPsExec -ArgumentList "\\$equipo -s -accepteula $cmd" -Wait -WindowStyle Hidden
            Start-Sleep -Seconds 3
            if (Test-Path $archivoRemoto) {
                Copy-Item -Path $archivoRemoto -Destination $archivoLocal -Force -ErrorAction SilentlyContinue
                Remove-Item $archivoRemoto -Force -ErrorAction SilentlyContinue
            } else {
                Escribir-Log -Texto "❌ No se pudo recuperar la lista de DCs remotos."
                return
            }
            $contenido = Get-Content $archivoLocal
            Remove-Item $archivoLocal -Force -ErrorAction SilentlyContinue
            $dcs = $contenido | Where-Object { $_ -match "\\" } | ForEach-Object {
                ($_ -split "\\")[-1].Trim()
            }
        } else {
            $dcs = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).DomainControllers | ForEach-Object { $_.Name }
        }
        if (-not $dcs -or $dcs.Count -eq 0) {
            Escribir-Log -Texto "❌ No se encontraron DCs."
            return
        }
        foreach ($dc in $dcs) {
            try {
                $ping = Test-Connection -ComputerName $dc -Count 1 -Quiet -ErrorAction SilentlyContinue
                if ($ping) {
                    $txtLog.SelectionColor = [System.Drawing.Color]::DarkGreen
                    $txtLog.AppendText("✅ DC accesible: $dc`n")
                } else {
                    $txtLog.SelectionColor = [System.Drawing.Color]::Red
                    $txtLog.AppendText("❌ DC inaccesible: $dc`n")
                }
            } catch {
                Invoke-SafeLog "⚠️ Error probando DC $dc $_" -Level Warning
            }
        }
        $txtLog.SelectionColor = [System.Drawing.Color]::Black
    } catch {
        Escribir-Log -Texto "❌ Error en controladores de dominio: $_"
    }
}

# --- Diagnostico-GPOsAplicadas ---
function Diagnostico-GPOsAplicadas {
    param([string]$equipo)
    try {
        Escribir-Log -Texto "🧾 Obteniendo GPOs en $equipo`n"
        $esRemoto = -not (Is-Local $equipo)
        $rutaLocal = "$env:TEMP\gpresult_$equipo.html"
        if ($esRemoto) {
            if (-not (Test-Path $global:RutaPsExec)) {
                Invoke-SafeLog -Texto "❌ PsExec no encontrado: $global:RutaPsExec" -Color ([System.Drawing.Color]::Red)
                return
            }
            $archivoRemoto = "\\$equipo\C$\Temp\gpresult.html"
            $cmd = "cmd.exe /c gpresult /H C:\Temp\gpresult.html /F"
            Start-Process -FilePath $global:RutaPsExec -ArgumentList "\\$equipo -s -accepteula $cmd" -Wait -WindowStyle Hidden
            Start-Sleep -Seconds 3
            if (Test-Path $archivoRemoto) {
                Copy-Item -Path $archivoRemoto -Destination $rutaLocal -Force -ErrorAction SilentlyContinue
                Remove-Item $archivoRemoto -Force -ErrorAction SilentlyContinue
            } else {
                Escribir-Log -Texto "❌ GPOs: No se pudo recuperar archivo remoto."
                return
            }
        } else {
            $rutaLocal = "$env:TEMP\gpresult_local.html"
            gpresult /H $rutaLocal /F | Out-Null
        }
        if (-not (Test-Path $rutaLocal)) {
            Escribir-Log -Texto "❌ GPOs: Archivo gpresult no encontrado."
            return
        }
        $html = Get-Content $rutaLocal -Raw
        Remove-Item $rutaLocal -Force -ErrorAction SilentlyContinue
        $textoPlano = $html -replace "<[^>]+>", ""
        $textoPlano = $textoPlano -replace "&nbsp;", " " -replace "&lt;", "<" -replace "&gt;", ">" -replace "\s{2,}", " "
        $lineas = $textoPlano -split "`n"
        $inicio = $false
        foreach ($linea in $lineas) {
            if ($linea -match "Applied Group Policy Objects") {
                $inicio = $true
                Escribir-Log -Texto "`n🔐 GPOs aplicadas:"
                continue
            }
            if ($inicio -and $linea.Trim() -eq "") { break }
            if ($inicio -and $linea.Trim() -ne "") {
                Escribir-Log -Texto " - $($linea.Trim())"
            }
        }
    } catch {
        Escribir-Log -Texto "❌ Error en GPOs: $_"
    }
}

# --- Diagnostico-DNSResolucion ---
function Diagnostico-DNSResolucion {
    param([string]$equipo)
    try {
        $esRemoto = -not (Is-Local $equipo)
        Escribir-Log -Texto "🌐 Resolución DNS en $equipo`n"
        $archivoLocal = "$env:TEMP\dns_resolucion_$equipo.txt"
        $archivoRemoto = "\\$equipo\C$\Temp\dns_resolucion.txt"
        if ($esRemoto) {
            if (-not (Test-Path $global:RutaPsExec)) {
                Invoke-SafeLog -Texto "❌ PsExec no encontrado: $global:RutaPsExec" -Color ([System.Drawing.Color]::Red)
                return
            }
            $cmd = 'setlocal enabledelayedexpansion & ' +
                    'echo Hostname: %COMPUTERNAME% > C:\Temp\dns_resolucion.txt & ' +
                    'for /f "tokens=2 delims=:" %%i in (''ipconfig ^| findstr /i "IPv4" ^| find /v "::"'') do set IP=%%i & ' +
                    'set IP=!IP: =! & ' +
                    'echo IP: !IP! >> C:\Temp\dns_resolucion.txt & ' +
                    'echo. >> C:\Temp\dns_resolucion.txt & ' +
                    'nslookup %COMPUTERNAME% >> C:\Temp\dns_resolucion.txt & ' +
                    'nslookup !IP! >> C:\Temp\dns_resolucion.txt'
            Start-Process -FilePath $global:RutaPsExec -ArgumentList "\\$equipo -s -accepteula cmd /v:on /c $cmd" -Wait -WindowStyle Hidden
            Start-Sleep -Seconds 3
            if (Test-Path $archivoRemoto) {
                Copy-Item -Path $archivoRemoto -Destination $archivoLocal -Force -ErrorAction SilentlyContinue
                Remove-Item $archivoRemoto -Force -ErrorAction SilentlyContinue
            } else {
                Escribir-Log -Texto "❌ DNS: No se pudo obtener resultado remoto."
                return
            }
        } else {
            $hostname = $env:COMPUTERNAME
            $ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.PrefixOrigin -ne "WellKnown" }).IPAddress
            $contenido = @("Hostname: $hostname","IP: $ip","","$(nslookup $hostname 2>&1)","","$(nslookup $ip 2>&1)")
            $contenido | Out-File -FilePath $archivoLocal -Encoding UTF8
        }
        if (-not (Test-Path $archivoLocal)) {
            Escribir-Log -Texto "❌ DNS: Archivo no leído."
            return
        }
        $contenido = Get-Content $archivoLocal
        Remove-Item $archivoLocal -Force -ErrorAction SilentlyContinue
        foreach ($linea in $contenido) {
            if ($linea -match "Non-existent|can't find") {
                $txtLog.SelectionColor = [System.Drawing.Color]::Red
            } elseif ($linea -match "Name:|Address:") {
                $txtLog.SelectionColor = [System.Drawing.Color]::DarkGreen
            } else {
                $txtLog.SelectionColor = [System.Drawing.Color]::Black
            }
            $txtLog.AppendText("$linea`n")
        }
        $txtLog.SelectionColor = [System.Drawing.Color]::Black
    } catch {
        Escribir-Log -Texto "❌ DNS Resolución: $_"
    }
}

# --- Diagnostico-DNSConfigurado ---
function Diagnostico-DNSConfigurado {
    param([string]$equipo)
    Escribir-Log -Texto "📡 Configuración DNS en $equipo..."
    try {
        if (Is-Local $equipo) {
            $adaptadores = Get-CimInstance -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled }
        } else {
            $adaptadores = Get-CimInstance -Class Win32_NetworkAdapterConfiguration -ComputerName $equipo | Where-Object { $_.IPEnabled }
        }
        if (-not $adaptadores) {
            Escribir-Log -Texto "⚠️ No se encontraron adaptadores en $equipo."
            return
        }
        foreach ($adaptador in $adaptadores) {
            try {
                $dns = ($adaptador.DNSServerSearchOrder) -join ", "
                $descripcion = $adaptador.Description
                Escribir-Log -Texto "🔧 Adaptador: $descripcion"
                Escribir-Log -Texto "🌐 DNS: $dns"
            } catch {
                Invoke-SafeLog "⚠️ Error procesando adaptador: $_" -Level Warning
            }
        }
    } catch {
        Escribir-Log -Texto "❌ DNS Configurado: $_"
    }
}

# --- Diagnostico-EstadoServicioDNS ---
function Diagnostico-EstadoServicioDNS {
    param([string]$equipo)
    try {
        Escribir-Log -Texto "🧩 Estado del servicio DNS Client en $equipo`n"
        $esRemoto = -not (Is-Local $equipo)
        $archivoLocal = "$env:TEMP\servicio_dns_$equipo.txt"
        $archivoRemoto = "\\$equipo\C$\Temp\servicio_dns.txt"
        if ($esRemoto) {
            if (-not (Test-Path $global:RutaPsExec)) {
                Invoke-SafeLog -Texto "❌ PsExec no encontrado: $global:RutaPsExec" -Color ([System.Drawing.Color]::Red)
                return
            }
            $cmd = 'sc query Dnscache > C:\Temp\servicio_dns.txt'
            Start-Process -FilePath $global:RutaPsExec -ArgumentList "\\$equipo -s -accepteula cmd /c $cmd" -Wait -WindowStyle Hidden
            Start-Sleep -Seconds 2
            if (Test-Path $archivoRemoto) {
                Copy-Item -Path $archivoRemoto -Destination $archivoLocal -Force -ErrorAction SilentlyContinue
                Remove-Item $archivoRemoto -Force -ErrorAction SilentlyContinue
            } else {
                Escribir-Log -Texto "❌ No se obtuvo estado DNS remoto."
                return
            }
        } else {
            $servicio = Get-Service -Name "Dnscache" -ErrorAction SilentlyContinue
            if (-not $servicio) {
                Escribir-Log -Texto "❌ No se pudo obtener servicio DNS Client."
                return
            }
            $estado = $servicio.Status
            $inicio = $servicio.StartType
            if ($estado -ne "Running") {
                $txtLog.SelectionColor = [System.Drawing.Color]::Red
                $txtLog.AppendText("❌ DNS Client no está en ejecución.`n")
            } else {
                $txtLog.SelectionColor = [System.Drawing.Color]::DarkGreen
                $txtLog.AppendText("✅ DNS Client activo.`n")
            }
            $txtLog.SelectionColor = [System.Drawing.Color]::Black
            Escribir-Log -Texto "   Inicio: $inicio"
            return
        }
        $lineas = Get-Content $archivoLocal
        Remove-Item $archivoLocal -Force -ErrorAction SilentlyContinue
        $estadoTexto = ""
        foreach ($linea in $lineas) {
            if ($linea -match "STATE") {
                $estadoTexto = ($linea -replace ".*STATE\s*:\s*\d+\s+", "").Trim()
                break
            }
        }
        if ($estadoTexto -match "RUNNING") {
            $txtLog.SelectionColor = [System.Drawing.Color]::DarkGreen
            $txtLog.AppendText("✅ DNS Client en ejecución.`n")
        } elseif ($estadoTexto) {
            $txtLog.SelectionColor = [System.Drawing.Color]::Red
            $txtLog.AppendText("❌ DNS Client: $estadoTexto`n")
        } else {
            Escribir-Log -Texto "⚠️ No se pudo interpretar el estado del servicio."
        }
        $txtLog.SelectionColor = [System.Drawing.Color]::Black
    } catch {
        Escribir-Log -Texto "❌ Error en estado DNS: $_"
    }
}

# --- Diagnostico-ServiciosCriticos ---
function Diagnostico-ServiciosCriticos {
    param([string]$equipo)
    try {
        Escribir-Log -Texto "⚙️ Verificando servicios críticos en $equipo`n"
        $serviciosRevisar = @("WinRM", "Winmgmt", "BITS", "LanmanWorkstation", "Netlogon")
        $esRemoto = -not (Is-Local $equipo)
        if ($esRemoto) {
            if (-not (Test-Path $global:RutaPsExec)) {
                Invoke-SafeLog -Texto "❌ PsExec no encontrado: $global:RutaPsExec" -Color ([System.Drawing.Color]::Red)
                return
            }
            $archivoLocal = "$env:TEMP\servicios_criticos_$equipo.txt"
            $archivoRemoto = "\\$equipo\C$\Temp\servicios_criticos.txt"
            $script = "@echo off`r`n"
            foreach ($serv in $serviciosRevisar) {
                $script += "echo --- $serv ---`r`n"
                $script += "sc query $serv`r`n"
            }
            $scriptPath = "$env:TEMP\check_servicios.cmd"
            $script | Out-File -FilePath $scriptPath -Encoding ASCII -Force
            Copy-Item -Path $scriptPath -Destination "\\$equipo\C$\Temp\check_servicios.cmd" -Force -ErrorAction SilentlyContinue
            $cmd = "cmd.exe /c C:\Temp\check_servicios.cmd > C:\Temp\servicios_criticos.txt"
            Start-Process -FilePath $global:RutaPsExec -ArgumentList "\\$equipo -s -accepteula $cmd" -Wait -WindowStyle Hidden
            Start-Sleep -Seconds 3
            if (Test-Path $archivoRemoto) {
                Copy-Item -Path $archivoRemoto -Destination $archivoLocal -Force -ErrorAction SilentlyContinue
                Remove-Item $archivoRemoto -Force -ErrorAction SilentlyContinue
            } else {
                Escribir-Log -Texto "❌ No se obtuvo el resultado de servicios críticos remoto."
                return
            }
            $lineas = Get-Content $archivoLocal
            Remove-Item $archivoLocal -Force -ErrorAction SilentlyContinue
            $servicioActual = ""
            foreach ($linea in $lineas) {
                if ($linea -match "^--- (.+) ---$") {
                    $servicioActual = $matches[1]
                    continue
                }
                if ($linea -match "STATE\s*:\s*\d+\s+(\w+)") {
                    $estadoServ = $matches[1]
                    $color = if ($estadoServ -eq "RUNNING") { [System.Drawing.Color]::DarkGreen } else { [System.Drawing.Color]::Red }
                    $txtLog.SelectionColor = $color
                    $txtLog.AppendText("🔧 $servicioActual → Estado: $estadoServ`n")
                }
            }
        } else {
            foreach ($nombre in $serviciosRevisar) {
                try {
                    $serv = Get-Service -Name $nombre -ErrorAction SilentlyContinue
                    if (-not $serv) {
                        $txtLog.SelectionColor = [System.Drawing.Color]::Red
                        $txtLog.AppendText("❌ Servicio no encontrado: $nombre`n")
                        continue
                    }
                    $estado = $serv.Status
                    $inicio = $serv.StartType
                    if ($estado -ne "Running") {
                        $txtLog.SelectionColor = [System.Drawing.Color]::Red
                        $txtLog.AppendText("❌ $nombre → Estado: $estado | Inicio: $inicio`n")
                    } else {
                        $txtLog.SelectionColor = [System.Drawing.Color]::DarkGreen
                        $txtLog.AppendText("✅ $nombre → Estado: $estado | Inicio: $inicio`n")
                    }
                } catch {
                    Invoke-SafeLog "⚠️ Error obteniendo servicio $nombre $_" -Level Warning
                }
            }
        }
        $txtLog.SelectionColor = [System.Drawing.Color]::Black
    } catch {
        Escribir-Log -Texto "❌ Error en servicios críticos: $_"
    }
}

# --- Diagnostico-ErroresServicios ---
function Diagnostico-ErroresServicios {
    param(
        [string]$equipo,
        [int]$Dias = 3
    )
    $NombreFuncion = "ErroresServicios"
    Invoke-SafeLog "[🔎] Analizando errores de servicios en $equipo (últimos $Dias días)..." -Category $NombreFuncion
    try {
        $EsLocal = Is-Local $equipo
        $fechaInicio = (Get-Date).AddDays(-$Dias).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        $filtroXML = @"
<QueryList>
  <Query Id='0' Path='System'>
    <Select Path='System'>
      *[System[Provider[@Name='Service Control Manager'] and Level=2 and TimeCreated[@SystemTime>='$fechaInicio']]]
    </Select>
  </Query>
</QueryList>
"@
        if ($EsLocal) {
            $eventos = Get-WinEvent -FilterXml $filtroXML -ErrorAction Stop
        } else {
            $eventos = Invoke-Command -ComputerName $equipo -ScriptBlock { param($f) Get-WinEvent -FilterXml $f -ErrorAction Stop } -ArgumentList $filtroXML -ErrorAction Stop
        }
        if ($eventos.Count -eq 0) {
            Invoke-SafeLog "[✔️] No se detectaron errores de servicios." -Category $NombreFuncion
        } else {
            foreach ($evento in $eventos) {
                try {
                    $hora = $evento.TimeCreated.ToString("yyyy-MM-dd HH:mm")
                    $mensaje = $evento.Message -replace "`r`n", " "
                    $servicio = $evento.Properties[0].Value
                    Invoke-SafeLog "[$hora] ❌ Servicio: $servicio - $mensaje" -Category $NombreFuncion -Level Error
                } catch {
                    Invoke-SafeLog "⚠️ Error procesando evento: $_" -Level Warning
                }
            }
        }
    } catch {
        Invoke-SafeLog "[⚠️] Error en errores de servicios: $($_.Exception.Message)" -Category $NombreFuncion -Level Warning
    }
}

# --- Diagnostico-Actualizaciones---
function Diagnostico-Actualizaciones {
    param([string]$equipo)
    try {
        Escribir-Log -Texto "🔄 Analizando historial de actualizaciones en $equipo..."

        $esRemoto = -not (Is-Local $equipo)
        $archivoLocal = "$env:TEMP\updates_result_$equipo.txt"
        $archivoRemoto = "\\$equipo\C$\Temp\updates_result.txt"

        if ($esRemoto) {
            if (-not (Test-Path $global:RutaPsExec)) {
                Escribir-Log -Texto "❌ PsExec no encontrado: $global:RutaPsExec"
                return
            }

            # Comando para obtener HotFixes
            $cmd = @'
powershell -Command "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 15 | ForEach-Object { 'KB: ' + $_.HotFixID + ' - ' + $_.Description + ' (' + $_.InstalledOn + ')' }" > C:\Temp\updates_result.txt
'@

            # Comando para obtener eventos de drivers recientes
            $cmdDriver = @'
powershell -Command "Get-WinEvent -LogName Setup -MaxEvents 50 | Where-Object { $_.Message -match 'driver' -and $_.TimeCreated -gt (Get-Date).AddDays(-15) } | ForEach-Object { '[' + $_.TimeCreated + '] ' + $_.Message }" >> C:\Temp\updates_result.txt
'@

            # Comando para verificar reinicio pendiente
            $cmdRestart = @'
powershell -Command "$pend = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction SilentlyContinue); if ($pend) { '⚠️ Reinicio pendiente detectado.' } else { '✅ Sin reinicio pendiente.' }" >> C:\Temp\updates_result.txt
'@

            # Comando para buscar actualizaciones pendientes usando COM de Windows Update
            $cmdPendientes = @'
powershell -Command "try {
    $updateSession = New-Object -ComObject Microsoft.Update.Session;
    $updateSearcher = $updateSession.CreateUpdateSearcher();
    $searchResult = $updateSearcher.Search('IsInstalled=0 and Type=''Software''');
    if ($searchResult.Updates.Count -gt 0) {
        '🔔 Hay actualizaciones pendientes: ' + $searchResult.Updates.Count;
    } else {
        '✅ No hay actualizaciones pendientes.';
    }
} catch {
    '❌ Error al buscar actualizaciones pendientes: ' + $_.Exception.Message;
}" >> C:\Temp\updates_result.txt
'@

            # Concatena todos los comandos para ejecución remota
            $scriptCmd = "$cmd & $cmdDriver & $cmdRestart & $cmdPendientes"
            $scriptPath = "$env:TEMP\get_updates.cmd"
            $scriptCmd | Set-Content -Path $scriptPath -Encoding ASCII
            Copy-Item -Path $scriptPath -Destination "\\$equipo\C$\Temp\get_updates.cmd" -Force
            Start-Process -FilePath $global:RutaPsExec -ArgumentList "\\$equipo -s -accepteula cmd /c C:\Temp\get_updates.cmd" -Wait -WindowStyle Hidden

            if (Wait-ForFile -FilePath $archivoRemoto -TimeoutSeconds 15) {
                Copy-Item -Path $archivoRemoto -Destination $archivoLocal -Force -ErrorAction SilentlyContinue
                Remove-Item $archivoRemoto -Force -ErrorAction SilentlyContinue
            } else {
                Escribir-Log -Texto "❌ Archivo de resultados no generado desde remoto."
                return
            }

        } else {
            # Obtener HotFixes locales
            $hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 15
            $contenido = $hotfixes | ForEach-Object { "KB: $($_.HotFixID) - $($_.Description) ($($_.InstalledOn))" }

            # Obtener eventos de drivers locales
            $drivers = Get-WinEvent -LogName Setup -MaxEvents 50 | Where-Object { $_.Message -match 'driver' -and $_.TimeCreated -gt (Get-Date).AddDays(-15) } | ForEach-Object { "[$($_.TimeCreated)] $($_.Message)" }

            # Verificar reinicio pendiente
            $rebootKey = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction SilentlyContinue
            $rebootStatus = if ($rebootKey) { "⚠️ Reinicio pendiente detectado." } else { "✅ Sin reinicio pendiente." }

            # Buscar actualizaciones pendientes usando COM de Windows Update
            try {
                $updateSession = New-Object -ComObject Microsoft.Update.Session
                $updateSearcher = $updateSession.CreateUpdateSearcher()
                $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software'")
                if ($searchResult.Updates.Count -gt 0) {
                    $pendientes = "🔔 Hay actualizaciones pendientes: $($searchResult.Updates.Count)"
                } else {
                    $pendientes = "✅ No hay actualizaciones pendientes."
                }
            } catch {
                $pendientes = "❌ Error al buscar actualizaciones pendientes: $_"
            }

            $contenido += "`n--- Drivers recientes ---"
            $contenido += $drivers
            $contenido += "`n--- Estado de reinicio ---"
            $contenido += $rebootStatus
            $contenido += "`n--- Actualizaciones pendientes ---"
            $contenido += $pendientes

            $contenido | Out-File -FilePath $archivoLocal -Encoding UTF8
        }

        if (-not (Test-Path $archivoLocal)) {
            Escribir-Log -Texto "❌ No se pudo leer resultados de actualizaciones."
            return
        }

        $lineas = Get-Content $archivoLocal
        foreach ($linea in $lineas) {
            if ($linea -match "KB" -or $linea -match "driver") {
                $txtLog.SelectionColor = [System.Drawing.Color]::Black
            }
            if ($linea -match "⚠️") {
                $txtLog.SelectionColor = [System.Drawing.Color]::Red
            } elseif ($linea -match "✅") {
                $txtLog.SelectionColor = [System.Drawing.Color]::DarkGreen
            }
            $txtLog.AppendText("$linea`n")
        }

        Remove-Item $archivoLocal -Force -ErrorAction SilentlyContinue
        $txtLog.SelectionColor = [System.Drawing.Color]::Black

    } catch {
        Escribir-Log -Texto "❌ Error en Diagnostico-Actualizaciones: $_"
    }
}

# --- Diagnostico-SFCScan ---
function Diagnostico-SFCScan {
    param([string]$equipo)
    try {
        Escribir-Log -Texto "🧱 Ejecutando SFC /scannow en $equipo`n"
        $esRemoto = -not (Is-Local $equipo)
        $archivoLocal = "$env:TEMP\sfc_result_$equipo.txt"
        if ($esRemoto) {
            if (-not (Test-Path $global:RutaPsExec)) {
                Invoke-SafeLog -Texto "❌ PsExec no encontrado: $global:RutaPsExec" -Color ([System.Drawing.Color]::Red)
                return
            }
            $cmd = "cmd.exe /c sfc /scannow > C:\Temp\sfc_result.txt"
            Start-Process -FilePath $global:RutaPsExec -ArgumentList "\\$equipo -s -accepteula $cmd" -Wait -WindowStyle Hidden
            $archivoRemoto = "\\$equipo\C$\Temp\sfc_result.txt"
            if (Wait-ForFile -FilePath $archivoRemoto -TimeoutSeconds 10) {
                Copy-Item -Path $archivoRemoto -Destination $archivoLocal -Force -ErrorAction SilentlyContinue
                Remove-Item $archivoRemoto -Force -ErrorAction SilentlyContinue
            } else {
                Escribir-Log -Texto "❌ SFC: Archivo remoto no generado en tiempo."
                return
            }
        } else {
            $archivoLocal = "$env:TEMP\sfc_result.txt"
            Escribir-Log -Texto "⌛ Ejecutando SFC localmente..."
            Start-Process -FilePath "cmd.exe" -ArgumentList "/c sfc /scannow > `"$archivoLocal`"" -Wait -WindowStyle Hidden
        }
        if (-not (Test-Path $archivoLocal)) {
            Escribir-Log -Texto "❌ SFC: No se pudo leer el resultado."
            return
        }
        $resultado = Get-Content $archivoLocal -Raw
        Remove-Item $archivoLocal -Force -ErrorAction SilentlyContinue
        if ($resultado -match "did not find any integrity violations") {
            Invoke-SafeLog -Texto "✅ SFC: Sin violaciones detectadas." -Color ([System.Drawing.Color]::DarkGreen)
        } elseif ($resultado -match "successfully repaired them") {
            Invoke-SafeLog -Texto "⚠️ SFC: Archivos dañados reparados." -Color ([System.Drawing.Color]::Orange)
        } elseif ($resultado -match "was unable to fix some of them") {
            Invoke-SafeLog -Texto "❌ SFC: Algunos archivos no se pudieron reparar." -Color ([System.Drawing.Color]::Red)
        } else {
            Invoke-SafeLog -Texto "ℹ️ SFC: Resultado inesperado:`n$resultado"
        }
    } catch {
        Escribir-Log -Texto "❌ Error en SFC: $_"
    }
}

# --- Diagnostico-CHKDSK ---
function Diagnostico-CHKDSK {
    param([string]$equipo)
    try {
        Escribir-Log -Texto "🧱 Ejecutando CHKDSK en C: de $equipo`n"
        $esRemoto = -not (Is-Local $equipo)
        if ($esRemoto) {
            $rutaTempRemota = "\\$equipo\C$\Temp"
            $archivoRemoto = "$rutaTempRemota\chkdsk_result.txt"
            $archivoLocal = "$env:TEMP\chkdsk_result_$equipo.txt"
            if (-not (Test-Path $global:RutaPsExec)) {
                Invoke-SafeLog -Texto "❌ PsExec no encontrado: $global:RutaPsExec" -Color ([System.Drawing.Color]::Red)
                return
            }
            $cmd = "cmd.exe /c chkdsk C: > C:\Temp\chkdsk_result.txt"
            Start-Process -FilePath $global:RutaPsExec -ArgumentList "\\$equipo -s -accepteula $cmd" -Wait -WindowStyle Hidden
            if (Wait-ForFile -FilePath $archivoRemoto -TimeoutSeconds 10) {
                Copy-Item -Path $archivoRemoto -Destination $archivoLocal -Force -ErrorAction SilentlyContinue
                Remove-Item $archivoRemoto -Force -ErrorAction SilentlyContinue
            } else {
                Escribir-Log -Texto "❌ CHKDSK: Archivo remoto no generado en tiempo."
                return
            }
        } else {
            $archivoLocal = "$env:TEMP\chkdsk_result.txt"
            Escribir-Log -Texto "⌛ Ejecutando CHKDSK localmente..."
            Start-Process -FilePath "cmd.exe" -ArgumentList "/c chkdsk C: > `"$archivoLocal`"" -Wait -WindowStyle Hidden
        }
        if (-not (Test-Path $archivoLocal)) {
            Escribir-Log -Texto "❌ CHKDSK: No se pudo leer el resultado."
            return
        }
        $resultado = Get-Content $archivoLocal -Raw
        Remove-Item $archivoLocal -Force -ErrorAction SilentlyContinue
        if ($resultado -match "no encontró problemas") {
            Invoke-SafeLog -Texto "✅ CHKDSK: Sin problemas detectados." -Color ([System.Drawing.Color]::DarkGreen)
        } elseif ($resultado -match "se encontraron problemas.*chkdsk /f") {
            Invoke-SafeLog -Texto "⚠️ CHKDSK: Errores encontrados; ejecutar 'chkdsk /f'." -Color ([System.Drawing.Color]::Orange)
        } elseif ($resultado -match "sectores dañados|irrecuperables|errores") {
            Invoke-SafeLog -Texto "❌ CHKDSK: Sectores dañados o errores graves detectados." -Color ([System.Drawing.Color]::Red)
        } else {
            Invoke-SafeLog -Texto "ℹ️ CHKDSK: Resultado:`n$resultado"
        }
    } catch {
        Escribir-Log -Texto "❌ Error en CHKDSK: $_"
    }
}

# --- Diagnostico-EventosArranque ---
function Diagnostico-EventosArranque {
    param(
        [string]$equipo,
        [int]$Dias = 3
    )
    $NombreFuncion = "EventosArranque"
    Invoke-SafeLog "[🔎] Analizando eventos de arranque en $equipo..." -Category $NombreFuncion
    try {
        $EsLocal = Is-Local $equipo
        $fechaInicio = (Get-Date).AddDays(-$Dias).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        $filtroXML = @"
<QueryList>
  <Query Id='0' Path='Microsoft-Windows-Diagnostics-Performance/Operational'>
    <Select Path='Microsoft-Windows-Diagnostics-Performance/Operational'>
      *[System[(EventID&gt;=100) and (EventID&lt;=200) and TimeCreated[@SystemTime&gt;='$fechaInicio']]]
    </Select>
  </Query>
</QueryList>
"@
        if ($EsLocal) {
            $eventos = Get-WinEvent -FilterXml $filtroXML -ErrorAction Stop
        } else {
            $eventos = Invoke-Command -ComputerName $equipo -ScriptBlock { param($f) Get-WinEvent -FilterXml $f -ErrorAction Stop } -ArgumentList $filtroXML -ErrorAction Stop
        }
        if ($eventos.Count -eq 0) {
            Invoke-SafeLog "[✔️] No se detectaron eventos de arranque recientes." -Category $NombreFuncion
        } else {
            foreach ($evento in $eventos) {
                try {
                    $hora = $evento.TimeCreated.ToString("yyyy-MM-dd HH:mm")
                    $mensaje = $evento.Message -replace "`r`n", " "
                    $id = $evento.Id
                    $nivel = $evento.LevelDisplayName
                    Invoke-SafeLog "[$hora] ⚙️ EventID $id - Nivel: $nivel - $mensaje" -Category $NombreFuncion -Level Info
                } catch {
                    Invoke-SafeLog "⚠️ Error procesando un evento: $_" -Level Warning
                }
            }
        }
    } catch {
        Invoke-SafeLog "[⚠️] Error en eventos de arranque: $($_.Exception.Message)" -Category $NombreFuncion -Level Warning
    }
}

# --- Diagnostico-ServiciosLentos ---
function Diagnostico-ServiciosLentos {
    param(
        [string]$equipo,
        [int]$Dias = 3,
        [int]$UmbralMs = 10000
    )
    $NombreFuncion = "ServiciosLentos"
    Invoke-SafeLog "[🔎] Buscando servicios lentos en $equipo..." -Category $NombreFuncion
    try {
        $EsLocal = Is-Local $equipo
        $fechaInicio = (Get-Date).AddDays(-$Dias).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        $filtroXML = @"
<QueryList>
  <Query Id='0' Path='Microsoft-Windows-Diagnostics-Performance/Operational'>
    <Select Path='Microsoft-Windows-Diagnostics-Performance/Operational'>
      *[System[(EventID=101) and TimeCreated[@SystemTime&gt;='$fechaInicio']]]
    </Select>
  </Query>
</QueryList>
"@
        if ($EsLocal) {
            $eventos = Get-WinEvent -FilterXml $filtroXML -ErrorAction Stop
        } else {
            $eventos = Invoke-Command -ComputerName $equipo -ScriptBlock { param($f) Get-WinEvent -FilterXml $f -ErrorAction Stop } -ArgumentList $filtroXML -ErrorAction Stop
        }
        if ($eventos.Count -eq 0) {
            Invoke-SafeLog "[✔️] No se encontraron servicios lentos recientes." -Category $NombreFuncion
        } else {
            foreach ($evento in $eventos) {
                try {
                    $datos = [xml]$evento.ToXml()
                    $tiempoMs = [int]$datos.Event.EventData.Data[1].'#text'
                    if ($tiempoMs -ge $UmbralMs) {
                        $servicio = $datos.Event.EventData.Data[0].'#text'
                        $tiempoSeg = [math]::Round($tiempoMs / 1000, 2)
                        $fecha = $evento.TimeCreated.ToString("yyyy-MM-dd HH:mm")
                        Invoke-SafeLog "[$fecha] 🐢 Servicio lento: [$servicio] tardó ${tiempoSeg}s." -Category $NombreFuncion -Level Info
                    }
                } catch {
                    Invoke-SafeLog "⚠️ Error procesando evento lento: $_" -Level Warning
                }
            }
        }
    } catch {
        Invoke-SafeLog "[⚠️] Error en servicios lentos: $($_.Exception.Message)" -Category $NombreFuncion -Level Warning
    }
}

# --- Diagnostico-AppsInicio ---
function Diagnostico-AppsInicio {
    param([string]$equipo)
    $NombreFuncion = "AplicacionesInicio"
    Invoke-SafeLog "[🔎] Recopilando apps al iniciar en $equipo..." -Category $NombreFuncion
    try {
        if (Is-Local $equipo) {
            $regPaths = @(
                "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
                "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
            )
            foreach ($path in $regPaths) {
                if (Test-Path $path) {
                    try {
                        Get-ItemProperty -Path $path | ForEach-Object {
                            $_.PSObject.Properties | Where-Object { $_.Name -notin @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider") } | ForEach-Object {
                                Invoke-SafeLog "🪪 Registro [$path] → $($_.Name): $($_.Value)" -Category $NombreFuncion
                            }
                        }
                    } catch {
                        Invoke-SafeLog "⚠️ Error procesando registro $path $_" -Level Warning
                    }
                }
            }
        } else {
            $scriptRemoto = {
                $salidas = @()
                $regPaths = @(
                    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
                    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
                )
                foreach ($path in $regPaths) {
                    if (Test-Path $path) {
                        try {
                            Get-ItemProperty -Path $path | ForEach-Object {
                                $_.PSObject.Properties | Where-Object { $_.Name -notin @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider") } | ForEach-Object {
                                    $salidas += "🪪 Registro [$path] → $($_.Name): $($_.Value)"
                                }
                            }
                        } catch {
                            $salidas += "⚠️ Error en registro $path $_"
                        }
                    }
                }
                return $salidas
            }
            $resultados = Invoke-Command -ComputerName $equipo -ScriptBlock $scriptRemoto -ErrorAction Stop
            foreach ($linea in $resultados) {
                Invoke-SafeLog $linea -Category $NombreFuncion
            }
        }
        Invoke-SafeLog "[✔️] Apps al iniciar completado." -Category $NombreFuncion
    } catch {
        Invoke-SafeLog "[⚠️] Error en apps al iniciar: $($_.Exception.Message)" -Category $NombreFuncion -Level Warning
    }
}

# --- Diagnostico-TareasProgramadas ---
function Diagnostico-TareasProgramadas {
    param([string]$equipo)
    $NombreFuncion = "TareasProgramadas"
    Invoke-SafeLog "[🔎] Analizando tareas programadas en $equipo..." -Category $NombreFuncion
    try {
        if (Is-Local $equipo) {
            $tareas = Get-ScheduledTask | Sort-Object TaskPath, TaskName
            foreach ($tarea in $tareas) {
                try {
                    $info = Get-ScheduledTaskInfo -TaskName $tarea.TaskName -TaskPath $tarea.TaskPath
                    $estado = if ($tarea.State -eq 'Disabled') { "⛔ Deshabilitada" } else { "✅ Activa" }
                    $esInicio = $false
                    if ($tarea.Triggers) {
                        foreach ($trigger in $tarea.Triggers) {
                            if ($trigger.TriggerType -eq 'Logon') {
                                $esInicio = $true
                                break
                            }
                        }
                    }
                    if ($tarea.Settings.StartWhenAvailable) { $esInicio = $true }
                    $linea = "📋 $($tarea.TaskPath)$($tarea.TaskName) [$estado, Última ejecución: $($info.LastRunTime), Resultado: $($info.LastTaskResult)]"
                    if ($esInicio) {
                        Invoke-SafeLog -Texto $linea -Category $NombreFuncion -Color ([System.Drawing.Color]::Orange)
                    } else {
                        Invoke-SafeLog -Texto $linea -Category $NombreFuncion
                    }
                } catch {
                    Invoke-SafeLog "⚠️ Error en tarea $($tarea.TaskName): $_" -Category $NombreFuncion -Level Warning
                }
            }
        } else {
            $scriptRemoto = {
                $salidas = @()
                $tareas = Get-ScheduledTask | Sort-Object TaskPath, TaskName
                foreach ($tarea in $tareas) {
                    try {
                        $info = Get-ScheduledTaskInfo -TaskName $tarea.TaskName -TaskPath $tarea.TaskPath
                        $estado = if ($tarea.State -eq 'Disabled') { "⛔ Deshabilitada" } else { "✅ Activa" }
                        $esInicio = $false
                        if ($tarea.Triggers) {
                            foreach ($trigger in $tarea.Triggers) {
                                if ($trigger.TriggerType -eq 'Logon') {
                                    $esInicio = $true
                                    break
                                }
                            }
                        }
                        if ($tarea.Settings.StartWhenAvailable) { $esInicio = $true }
                        $linea = "📋 $($tarea.TaskPath)$($tarea.TaskName) [$estado, Última ejecución: $($info.LastRunTime), Resultado: $($info.LastTaskResult)]"
                        $salidas += [PSCustomObject]@{
                            Text    = $linea
                            Startup = $esInicio
                        }
                    } catch {
                        $salidas += [PSCustomObject]@{
                            Text    = "⚠️ Error en tarea $($tarea.TaskName): $_"
                            Startup = $false
                        }
                    }
                }
                return $salidas
            }
            $resultados = Invoke-Command -ComputerName $equipo -ScriptBlock $scriptRemoto -ErrorAction Stop
            foreach ($item in $resultados) {
                if ($item.Startup) {
                    Invoke-SafeLog -Texto $item.Text -Category $NombreFuncion -Color ([System.Drawing.Color]::Orange)
                } else {
                    Invoke-SafeLog -Texto $item.Text -Category $NombreFuncion
                }
            }
        }
        Invoke-SafeLog "[✔️] Tareas programadas completado." -Category $NombreFuncion
    } catch {
        Invoke-SafeLog "[⚠️] Error en tareas programadas: $($_.Exception.Message)" -Category $NombreFuncion -Level Warning
    }
}

# --- Diagnostico-EventosRed ---
function Diagnostico-EventosRed {
    param([string]$equipo)
    $NombreFuncion = "EventosRed"
    Invoke-SafeLog "[🔎] Analizando eventos de red en $equipo..." -Category $NombreFuncion
    try {
        $EsLocal = Is-Local $equipo
        $FiltroXML = @"
<QueryList>
  <Query Id='0' Path='System'>
    <Select Path='System'>
      *[System[Provider[@Name='Microsoft-Windows-Tcpip'] or Provider[@Name='Microsoft-Windows-NDIS'] or Provider[@Name='Microsoft-Windows-DNS-Client'] and (Level=2 or Level=3 or Level=4)]]
    </Select>
  </Query>
</QueryList>
"@
        if ($EsLocal) {
            $eventos = Get-WinEvent -FilterXml $FiltroXML -MaxEvents 30 -ErrorAction Stop
        } else {
            $eventos = Invoke-Command -ComputerName $equipo -ScriptBlock { param($f) Get-WinEvent -FilterXml $f -MaxEvents 30 -ErrorAction Stop } -ArgumentList $FiltroXML -ErrorAction Stop
        }
        if ($eventos.Count -eq 0) {
            Invoke-SafeLog "✅ No se detectaron eventos críticos de red." -Category $NombreFuncion
        } else {
            foreach ($evento in $eventos) {
                try {
                    $mensaje = "🛑 [$($evento.TimeCreated)] $($evento.ProviderName) - $($evento.Id): $($evento.Message -replace "`r`n", ' ')"
                    Invoke-SafeLog $mensaje -Category $NombreFuncion
                } catch {
                    Invoke-SafeLog "⚠️ Error procesando evento de red: $_" -Level Warning
                }
            }
        }
        Invoke-SafeLog "[✔️] Eventos de red completados." -Category $NombreFuncion
    } catch {
        Invoke-SafeLog "[⚠️] Error en eventos de red: $($_.Exception.Message)" -Category $NombreFuncion -Level Warning
    }
}

# --- Diagnostico-EventosSistema ---
function Diagnostico-EventosSistema {
    param([string]$equipo)
    $NombreFuncion = "EventosSistema"
    Invoke-SafeLog "[🔎] Analizando eventos del sistema en $equipo..." -Category $NombreFuncion
    try {
        $EsLocal = Is-Local $equipo
        $FiltroXML = @"
<QueryList>
  <Query Id='0' Path='System'>
    <Select Path='System'>
      *[System[(Level=1 or Level=2 or Level=3) and (EventID=41 or EventID=55 or EventID=56 or EventID=1001 or EventID=7026 or EventID=7000 or EventID=7001)]]
    </Select>
  </Query>
</QueryList>
"@
        if ($EsLocal) {
            $eventos = Get-WinEvent -FilterXml $FiltroXML -MaxEvents 30 -ErrorAction Stop
        } else {
            $eventos = Invoke-Command -ComputerName $equipo -ScriptBlock { param($f) Get-WinEvent -FilterXml $f -MaxEvents 30 -ErrorAction Stop } -ArgumentList $FiltroXML -ErrorAction Stop
        }
        if ($eventos.Count -eq 0) {
            Invoke-SafeLog "✅ No se encontraron errores del sistema." -Category $NombreFuncion
        } else {
            foreach ($evento in $eventos) {
                try {
                    $mensaje = "🛑 [$($evento.TimeCreated)] $($evento.ProviderName) - $($evento.Id): $($evento.Message -replace "`r`n", ' ')"
                    Invoke-SafeLog $mensaje -Category $NombreFuncion
                } catch {
                    Invoke-SafeLog "⚠️ Error procesando evento del sistema: $_" -Level Warning
                }
            }
        }
        Invoke-SafeLog "[✔️] Eventos del sistema finalizados." -Category $NombreFuncion
    } catch {
        Invoke-SafeLog "[⚠️] Error en eventos del sistema: $($_.Exception.Message)" -Category $NombreFuncion -Level Warning
    }
}

# --- Diagnostico-EventosSeguridad ---
function Diagnostico-EventosSeguridad {
    param([string]$equipo)
    $NombreFuncion = "EventosSeguridad"
    Invoke-SafeLog "[🔎] Analizando eventos de seguridad en $equipo..." -Category $NombreFuncion
    try {
        $EsLocal = Is-Local $equipo
        $FiltroXML = @"
<QueryList>
  <Query Id='0' Path='Security'>
    <Select Path='Security'>
      *[System[(EventID=4625 or EventID=4624 or EventID=4740)]]
    </Select>
  </Query>
</QueryList>
"@
        if ($EsLocal) {
            $eventos = Get-WinEvent -FilterXml $FiltroXML -MaxEvents 30 -ErrorAction Stop
        } else {
            $eventos = Invoke-Command -ComputerName $equipo -ScriptBlock { param($f) Get-WinEvent -FilterXml $f -MaxEvents 30 -ErrorAction Stop } -ArgumentList $FiltroXML -ErrorAction Stop
        }
        if ($eventos.Count -eq 0) {
            Invoke-SafeLog "✅ No se detectaron eventos de seguridad relevantes." -Category $NombreFuncion
        } else {
            foreach ($evento in $eventos) {
                try {
                    $tipo = switch ($evento.Id) {
                        4624 { "✔️ Inicio de sesión exitoso" }
                        4625 { "❌ Inicio de sesión fallido" }
                        4740 { "🔒 Cuenta bloqueada" }
                        default { "Evento Seguridad" }
                    }
                    $mensaje = "$tipo [$($evento.TimeCreated)] $($evento.ProviderName) - $($evento.Id): $($evento.Message -replace "`r`n", ' ')"
                    Invoke-SafeLog $mensaje -Category $NombreFuncion
                } catch {
                    Invoke-SafeLog "⚠️ Error procesando evento de seguridad: $_" -Level Warning
                }
            }
        }
        Invoke-SafeLog "[✔️] Eventos de seguridad finalizados." -Category $NombreFuncion
    } catch {
        Invoke-SafeLog "[⚠️] Error en eventos de seguridad: $($_.Exception.Message)" -Category $NombreFuncion -Level Warning
    }
}

# --- Diagnostico-EventosSoftwareCorporativo ---
function Diagnostico-EventosSoftwareCorporativo {
    param([string]$equipo)
    $NombreFuncion = "EventosSoftwareCorporativo"
    Invoke-SafeLog "[🔎] Analizando eventos de Aplicacións en $equipo..." -Category $NombreFuncion
    try {
        $EsLocal = Is-Local $equipo
        $FiltroXML = @"
<QueryList>
  <Query Id='0' Path='Application'>
    <Select Path='Application'>
      *[System[Provider[@Name='MsiInstaller' or @Name='SCCM Client' or @Name='Windows Defender' or @Name='Microsoft-Windows-WindowsUpdateClient'] and (Level=1 or Level=2)]]
    </Select>
  </Query>
  <Query Id='1' Path='System'>
    <Select Path='System'>
      *[System[Provider[@Name='Service Control Manager' or @Name='Windows Update Agent'] and (Level=1 or Level=2)]]
    </Select>
  </Query>
</QueryList>
"@
        if ($EsLocal) {
            $eventos = Get-WinEvent -FilterXml $FiltroXML -MaxEvents 30 -ErrorAction Stop
        } else {
            $eventos = Invoke-Command -ComputerName $equipo -ScriptBlock { param($f) Get-WinEvent -FilterXml $f -MaxEvents 30 -ErrorAction Stop } -ArgumentList $FiltroXML -ErrorAction Stop
        }
        if ($eventos.Count -eq 0) {
            Invoke-SafeLog "✅ No se detectaron eventos de Aplicacións recientes." -Category $NombreFuncion
        } else {
            foreach ($evento in $eventos) {
                try {
                    $mensaje = "⚠️ [$($evento.TimeCreated)] $($evento.ProviderName) - $($evento.Id): $($evento.Message -replace "`r`n", ' ')"
                    Invoke-SafeLog $mensaje -Category $NombreFuncion
                } catch {
                    Invoke-SafeLog "⚠️ Error procesando evento de Aplicacións: $_" -Level Warning
                }
            }
        }
        Invoke-SafeLog "[✔️] Eventos de Aplicacións finalizados." -Category $NombreFuncion
    } catch {
        Invoke-SafeLog "[⚠️] Error en eventos de Aplicacións: $($_.Exception.Message)" -Category $NombreFuncion -Level Warning
    }
}

# --- Guardar-LogComoTXT ---
function Guardar-LogComoTXT {
    param([System.Windows.Forms.RichTextBox]$txtLog)
    try {
        $res = [System.Windows.Forms.MessageBox]::Show(
            "¿Deseas guardar el resultado del análisis como archivo TXT?",
            "Guardar resultados",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question
        )
        if ($res -ne [System.Windows.Forms.DialogResult]::Yes) { return }
        $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveDialog.Title = "Guardar resultado como TXT"
        $saveDialog.Filter = "Archivo de texto (*.txt)|*.txt"
        $saveDialog.FileName = "Diagnostico_$((Get-Date).ToString('yyyyMMdd_HHmmss')).txt"
        if ($saveDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $ruta = $saveDialog.FileName
            $fecha = Get-Date -Format "dddd dd MMMM yyyy - HH:mm:ss"
            $titulo = "INFORME DE DIAGNÓSTICO DE EQUIPO"
            $separador = "=" * 80
            $contenido = @()
            $contenido += $separador
            $contenido += $titulo
            $contenido += "Fecha: $fecha"
            $contenido += "Equipo analizado: $($txtEquipo.Text.Trim())"
            $contenido += $separador
            $contenido += ""
            $contenido += $txtLog.Lines | Where-Object { $_.Trim() -ne "" }
            $contenido | Out-File -FilePath $ruta -Encoding UTF8
            [System.Windows.Forms.MessageBox]::Show("✅ Resultado guardado en:`n$ruta", "Exportación completada", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        }
    } catch {
        [System.Windows.Forms.MessageBox]::Show("❌ Error al guardar el archivo TXT:`n$_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
}

# --- Diagnostico-DISM ---
function Diagnostico-DISM {
    param([string]$equipo)
    try {
        Escribir-Log -Texto "🛠️ Ejecutando DISM en $equipo`n"
        $esRemoto = -not (Is-Local $equipo)
        $rutaBase = "$env:TEMP\dism_$equipo"
        New-Item -Path $rutaBase -ItemType Directory -Force | Out-Null
        $archivoCheck = "$rutaBase\dism_check.txt"
        $archivoScan  = "$rutaBase\dism_scan.txt"
        $archivoRestore = "$rutaBase\dism_restore.txt"
        $comandos = @(
            @{Nombre="CheckHealth"; Comando="dism /online /cleanup-image /checkhealth"; Archivo=$archivoCheck},
            @{Nombre="ScanHealth";  Comando="dism /online /cleanup-image /scanhealth";  Archivo=$archivoScan},
            @{Nombre="RestoreHealth"; Comando="dism /online /cleanup-image /restorehealth"; Archivo=$archivoRestore}
        )
        foreach ($item in $comandos) {
            $nombre = $item.Nombre
            $comando = $item.Comando
            $archivo = $item.Archivo
            Escribir-Log -Texto "▶️ DISM $nombre..."
            if ($esRemoto) {
                if (-not (Test-Path $global:RutaPsExec)) {
                    Invoke-SafeLog -Texto "❌ PsExec no encontrado: $global:RutaPsExec" -Color ([System.Drawing.Color]::Red)
                    return
                }
                $archivoRemoto = "\\$equipo\C$\Temp\dism_result_$nombre.txt"
                $cmd = "cmd.exe /c $comando > C:\Temp\dism_result_$nombre.txt"
                Start-Process -FilePath $global:RutaPsExec -ArgumentList "\\$equipo -s -accepteula $cmd" -Wait -WindowStyle Hidden
                if (Wait-ForFile -FilePath $archivoRemoto -TimeoutSeconds 10) {
                    # Continuar
                } else {
                    Escribir-Log -Texto "❌ DISM $nombre archivo remoto no generado."
                    return
                }
                if (Test-Path $archivoRemoto) {
                    Copy-Item -Path $archivoRemoto -Destination $archivo -Force -ErrorAction SilentlyContinue
                    Remove-Item $archivoRemoto -Force -ErrorAction SilentlyContinue
                } else {
                    Invoke-SafeLog -Texto "❌ DISM $nombre resultado no encontrado." -Color ([System.Drawing.Color]::Red)
                    continue
                }
            } else {
                Start-Process -FilePath "cmd.exe" -ArgumentList "/c $comando > `"$archivo`"" -Wait -WindowStyle Hidden
            }
            if (-not (Test-Path $archivo)) {
                Invoke-SafeLog -Texto "❌ DISM $nombre resultado no generado." -Color ([System.Drawing.Color]::Red)
                continue
            }
            $contenido = Get-Content $archivo -Raw
            Remove-Item $archivo -Force -ErrorAction SilentlyContinue
            if ($contenido -match "No component store corruption detected") {
                Invoke-SafeLog -Texto "✅ DISM $nombre Sin problemas." -Color ([System.Drawing.Color]::DarkGreen)
            } elseif ($contenido -match "The restore operation completed successfully") {
                Invoke-SafeLog -Texto "✅ DISM $nombre Reparación completada." -Color ([System.Drawing.Color]::DarkGreen)
            } elseif ($contenido -match "The operation completed successfully") {
                Invoke-SafeLog -Texto "✅ DISM $nombre Operación exitosa." -Color ([System.Drawing.Color]::DarkGreen)
            } elseif ($contenido -match "Error|failed|corrup") {
                Invoke-SafeLog -Texto "❌ DISM $nombre Errores detectados." -Color ([System.Drawing.Color]::Red)
                Invoke-SafeLog -Texto $contenido
            } else {
                Invoke-SafeLog -Texto "ℹ️ DISM $nombre Resultado:`n$contenido"
            }
        }
    } catch {
        Escribir-Log -Texto "❌ Error en DISM: $_"
    }
}
# --- Diagnostico-WinlogonPerfil ---
function Diagnostico-WinlogonPerfil {
    param([string]$equipo)
    try {
        Escribir-Log -Texto "🔍 Consultando eventos Winlogon/Perfil de Usuario en $equipo..."
        $esLocal = Is-Local $equipo
        $filterXML = @"
<QueryList>
  <Query Id='0' Path='Microsoft-Windows-Winlogon/Operational'>
    <Select Path='Microsoft-Windows-Winlogon/Operational'>*[System[(Level=2 or Level=3)]]</Select>
  </Query>
  <Query Id='1' Path='Microsoft-Windows-User Profile Service/Operational'>
    <Select Path='Microsoft-Windows-User Profile Service/Operational'>*[System[(Level=2 or Level=3)]]</Select>
  </Query>
</QueryList>
"@
        if ($esLocal) {
            $eventos = Get-WinEvent -FilterXml $filterXML -MaxEvents 50 -ErrorAction Stop
        } else {
            $eventos = Get-WinEvent -ComputerName $equipo -FilterXml $filterXML -MaxEvents 50 -ErrorAction Stop
        }
        if ($eventos.Count -eq 0) {
            Escribir-Log -Texto "✅ No se encontraron eventos relevantes en Winlogon/Perfil."
        } else {
            foreach ($evento in $eventos) {
                $mensaje = "$($evento.TimeCreated) - ID $($evento.Id): $($evento.Message -replace "`r`n", " ")"
                Escribir-Log -Texto $mensaje
            }
        }
    } catch {
        Escribir-Log -Texto "❌ Error en Diagnostico-WinlogonPerfil: $_"
    }
}

# --- Diagnostico-LockUnlockLogon ---
function Diagnostico-LockUnlockLogon {
    param([string]$equipo)
    try {
        Escribir-Log -Texto "🔍 Consultando eventos de Lock/Unlock y Logon en $equipo..."
        $esLocal = Is-Local $equipo
        $filterXML = @"
<QueryList>
  <Query Id='0' Path='Security'>
    <Select Path='Security'>*[System[(EventID=4800 or EventID=4801 or EventID=4624 or EventID=4647)]]</Select>
  </Query>
</QueryList>
"@
        if ($esLocal) {
            $eventos = Get-WinEvent -FilterXml $filterXML -MaxEvents 50 -ErrorAction Stop
        } else {
            $eventos = Get-WinEvent -ComputerName $equipo -FilterXml $filterXML -MaxEvents 50 -ErrorAction Stop
        }
        if ($eventos.Count -eq 0) {
            Escribir-Log -Texto "✅ No se encontraron eventos de Lock/Unlock/Logon."
        } else {
            foreach ($evento in $eventos) {
                $mensaje = "$($evento.TimeCreated) - ID $($evento.Id): $($evento.Message -replace "`r`n", " ")"
                Escribir-Log -Texto $mensaje
            }
        }
    } catch {
        Escribir-Log -Texto "❌ Error en Diagnostico-LockUnlockLogon: $_"
    }
}

# --- Diagnostico-WER ---
function Diagnostico-WER {
    param([string]$equipo)
    try {
        Escribir-Log -Texto "🔍 Analizando Windows Error Reports (.WER) en $equipo..."
        $esLocal = Is-Local $equipo
        $reportDirs = @()
        if ($esLocal) {
            $reportDirs += "C:\ProgramData\Microsoft\Windows\WER\ReportQueue"
            $userWer = Join-Path $env:LOCALAPPDATA "Microsoft\Windows\WER"
            if (Test-Path $userWer) { $reportDirs += $userWer }
        } else {
            # Asumimos acceso al recurso compartido C$
            $reportDirs += "\\$equipo\C$\ProgramData\Microsoft\Windows\WER\ReportQueue"
            # Para perfiles de usuario, podría ser necesario conocer el path exacto
        }
        foreach ($dir in $reportDirs) {
            if (Test-Path $dir) {
                Escribir-Log -Texto "📂 Revisando directorio: $dir"
                $werFiles = Get-ChildItem -Path $dir -Filter *.wer -Recurse -ErrorAction SilentlyContinue
                foreach ($file in $werFiles) {
                    $contenido = Get-Content $file.FullName -Raw
                    $appName = ($contenido | Select-String -Pattern "AppName=(.+)" | ForEach-Object { $_.Matches[0].Groups[1].Value }).Trim()
                    $faultModule = ($contenido | Select-String -Pattern "FaultModule=(.+)" | ForEach-Object { $_.Matches[0].Groups[1].Value }).Trim()
                    $exceptionCode = ($contenido | Select-String -Pattern "ExceptionCode=(.+)" | ForEach-Object { $_.Matches[0].Groups[1].Value }).Trim()
                    Escribir-Log -Texto "📝 WER: App=$appName, Module=$faultModule, Code=$exceptionCode"
                }
            } else {
                Escribir-Log -Texto "⚠️ Directorio no encontrado: $dir"
            }
        }
    } catch {
        Escribir-Log -Texto "❌ Error en Diagnostico-WER: $_"
    }
}

# --- Diagnostico-ReliabilityMonitor ---
function Diagnostico-ReliabilityMonitor {
    param([string]$equipo)
    try {
        Escribir-Log -Texto "🔍 Consultando Reliability Monitor en $equipo..."
        $esLocal = Is-Local $equipo
        $filterXML = @"
<QueryList>
  <Query Id='0' Path='Microsoft-Windows-Reliability/Operational'>
    <Select Path='Microsoft-Windows-Reliability/Operational'>*[System[(Level=1 or Level=2)]]</Select>
  </Query>
</QueryList>
"@
        if ($esLocal) {
            $eventos = Get-WinEvent -FilterXml $filterXML -MaxEvents 30 -ErrorAction Stop
        } else {
            $eventos = Get-WinEvent -ComputerName $equipo -FilterXml $filterXML -MaxEvents 30 -ErrorAction Stop
        }
        if ($eventos.Count -eq 0) {
            Escribir-Log -Texto "✅ No se detectaron incidencias en Reliability Monitor."
        } else {
            foreach ($evento in $eventos) {
                $mensaje = "$($evento.TimeCreated) - ID $($evento.Id): $($evento.Message -replace "`r`n", " ")"
                Escribir-Log -Texto $mensaje
            }
        }
    } catch {
        Escribir-Log -Texto "❌ Error en Diagnostico-ReliabilityMonitor: $_"
    }
}

# --- Diagnostico-PostHang (Diagnóstico tras reinicio) ---
function Diagnostico-PostHang {
    param([string]$equipo)
    try {
        Escribir-Log -Texto "🔄 Ejecutando diagnóstico post-cuelgue en $equipo..."
        # Definir el intervalo de tiempo a analizar (últimos 30 minutos)
        $fechaInicio = (Get-Date).AddMinutes(-30).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        
        # Eventos recientes del sistema
        Escribir-Log -Texto "`n🕒 Eventos recientes del sistema (últimos 30 minutos):"
        $filterXML = @"
<QueryList>
  <Query Id='0' Path='System'>
    <Select Path='System'>*[System[TimeCreated[@SystemTime>='$fechaInicio']]]</Select>
  </Query>
</QueryList>
"@
        $esLocal = Is-Local $equipo
        if ($esLocal) {
            $eventosRecientes = Get-WinEvent -FilterXml $filterXML -MaxEvents 20 -ErrorAction Stop
        } else {
            $eventosRecientes = Get-WinEvent -ComputerName $equipo -FilterXml $filterXML -MaxEvents 20 -ErrorAction Stop
        }
        if ($eventosRecientes.Count -eq 0) {
            Escribir-Log -Texto "✅ No se encontraron eventos recientes en System."
        } else {
            foreach ($evento in $eventosRecientes) {
                $mensaje = "$($evento.TimeCreated) - ID $($evento.Id): $($evento.Message -replace "`r`n", " ")"
                Escribir-Log -Texto $mensaje
            }
        }
        
        # Ejecutar los análisis de los módulos definidos
        Escribir-Log -Texto "`n🔍 Ejecutando análisis de Winlogon/Perfil de Usuario..."
        Diagnostico-WinlogonPerfil -equipo $equipo
        Start-Sleep -Milliseconds 500
        
        Escribir-Log -Texto "`n🔍 Ejecutando análisis de Lock/Unlock + Logon..."
        Diagnostico-LockUnlockLogon -equipo $equipo
        Start-Sleep -Milliseconds 500
        
        Escribir-Log -Texto "`n🔍 Ejecutando análisis de .WER..."
        Diagnostico-WER -equipo $equipo
        Start-Sleep -Milliseconds 500
        
        Escribir-Log -Texto "`n🔍 Ejecutando análisis de Reliability Monitor..."
        Diagnostico-ReliabilityMonitor -equipo $equipo
        Start-Sleep -Milliseconds 500
        
        Escribir-Log -Texto "`n✅ Diagnóstico post-cuelgue completado."
    } catch {
        Escribir-Log -Texto "❌ Error en Diagnostico-PostHang: $_"
    }
}

# =========================================
# BLOQUE: Evento al pulsar "Analizar"
# =========================================
$btnAnalizar.Add_Click({
    $txtLog.Clear()
    $equipo = $txtEquipo.Text.Trim()
    if (-not $equipo) { $equipo = $env:COMPUTERNAME }
    Escribir-Log -Texto "Iniciando diagnóstico para $equipo"
    Escribir-Log -Separador
    $analisisSeleccionados = @()
    foreach ($nodo in $treeAnalisis.Nodes) {
        foreach ($subNodo in $nodo.Nodes) {
            if ($subNodo.Checked) {
                $analisisSeleccionados += @{
                    Categoria = $nodo.Text
                    Subcategoria = $subNodo.Text
                }
            }
        }
    }
    if ($analisisSeleccionados.Count -eq 0) {
        Escribir-Log -Texto "⚠️ No se seleccionó ningún análisis."
        return
    }
    foreach ($bloque in $analisisSeleccionados) {
        Escribir-Log -Separador
        Escribir-Log -Texto "🧪 Análisis: $($bloque.Categoria) → $($bloque.Subcategoria)"
        Escribir-Log -Texto "▶️ Ejecutando bloque..."
        switch ($bloque.Subcategoria) {
            "Conectividad" { Diagnostico-Conectividad -equipo $equipo }
            "DHCP" { Diagnostico-DHCP -equipo $equipo }
            "Adaptador de red" { Diagnostico-AdaptadorRed -equipo $equipo }
            "Uso de CPU/RAM" { Diagnostico-Rendimiento -equipo $equipo }
            "Procesos activos" { Diagnostico-ProcesosActivos -equipo $equipo }
            "Espacio en disco" { Diagnostico-EspacioDisco -equipo $equipo }
            "Eventos críticos" { Diagnostico-EventosCriticos -equipo $equipo }
            "Estado SMART" { Diagnostico-DiscoSMART -equipo $equipo }
            "Drivers y reinicios" { Diagnostico-DriversYReinicios -equipo $equipo }
            "Estado del dominio" { Diagnostico-EstadoDominio -equipo $equipo }
            "Controladores accesibles" { Diagnostico-ControladoresDominio -equipo $equipo }
            "GPOs aplicadas" { Diagnostico-GPOsAplicadas -equipo $equipo }
            "Resolución directa/inversa" { Diagnostico-DNSResolucion -equipo $equipo }
            "DNS configurado" { Diagnostico-DNSConfigurado -equipo $equipo }
            "Estado del servicio DNS" { Diagnostico-EstadoServicioDNS -equipo $equipo }
            "WinRM, WMI, BITS" { Diagnostico-ServiciosCriticos -equipo $equipo }
            "Errores de servicio" { Diagnostico-ErroresServicios -equipo $equipo }
            "Actualizaciones recientes" { Diagnostico-Actualizaciones -equipo $equipo }
            "SFC /scannow" { Diagnostico-SFCScan -equipo $equipo }
            "CHKDSK" { Diagnostico-CHKDSK -equipo $equipo }
            "DISM /Online /Cleanup-Image" { Diagnostico-DISM -equipo $equipo }
            "Tiempos de arranque" { Diagnostico-EventosArranque -equipo $equipo }
            "Servicios lentos" { Diagnostico-ServiciosLentos -equipo $equipo }
            "Apps al iniciar" { Diagnostico-AppsInicio -equipo $equipo }
            "Tareas programadas" { Diagnostico-TareasProgramadas -equipo $equipo }
            "Red" { Diagnostico-EventosRed -equipo $equipo }
            "Sistema" { Diagnostico-EventosSistema -equipo $equipo }
            "Seguridad" { Diagnostico-EventosSeguridad -equipo $equipo }
            "Aplicacións" { Diagnostico-EventosSoftwareCorporativo -equipo $equipo }
            "Winlogon / Perfil de Usuario" { Diagnostico-WinlogonPerfil -equipo $equipo }
            "Lock/Unlock + Logon" { Diagnostico-LockUnlockLogon -equipo $equipo }
            "Análisis .WER" { Diagnostico-WER -equipo $equipo }
            "Reliability Monitor" { Diagnostico-ReliabilityMonitor -equipo $equipo }
            "Diagnostico-PostHang" { Diagnostico-PostHang -equipo $equipo }
            "Análisis de red" {
                Diagnostico-Conectividad -equipo $equipo
                Diagnostico-DHCP -equipo $equipo
                Diagnostico-AdaptadorRed -equipo $equipo
                Diagnostico-DNSResolucion -equipo $equipo
                Diagnostico-DNSConfigurado -equipo $equipo
                Diagnostico-EstadoServicioDNS -equipo $equipo
                Diagnostico-EventosRed -equipo $equipo
            }
            "Análisis de rendimiento" {
                Diagnostico-Rendimiento -equipo $equipo
                Diagnostico-ProcesosActivos -equipo $equipo
                Diagnostico-EspacioDisco -equipo $equipo
                Diagnostico-EventosArranque -equipo $equipo
                Diagnostico-ServiciosLentos -equipo $equipo
            }
            "Análisis de problemas" {
                Diagnostico-EventosCriticos -equipo $equipo
                Diagnostico-DriversYReinicios -equipo $equipo
                Diagnostico-SFCScan -equipo $equipo
                Diagnostico-CHKDSK -equipo $equipo
                Diagnostico-ErroresServicios -equipo $equipo
                Diagnostico-EventosSistema -equipo $equipo
                Diagnostico-EventosSeguridad -equipo $equipo
                Diagnostico-EventosSoftwareCorporativo -equipo $equipo
            }
            default { Escribir-Log -Texto "ℹ️ Módulo no implementado." }
        }
        Start-Sleep -Milliseconds 500
        Escribir-Log -Texto "✅ Finalizado: $($bloque.Subcategoria)"
    }
    Escribir-Log -Separador
    Escribir-Log -Texto "🟢 Diagnóstico finalizado."
    Guardar-LogComoTXT -txtLog $txtLog
})

# =========================================
# BLOQUE: Lanzar formulario
# =========================================
[void]$form.ShowDialog()