🛠️ Herramienta de Diagnóstico de Equipos (PowerShell GUI)
🧩 Descripción general
Aplicación avanzada en PowerShell con interfaz gráfica (WinForms) para realizar diagnósticos completos sobre equipos Windows, tanto locales como remotos. Pensada para técnicos de soporte, permite verificar múltiples aspectos del sistema de forma automatizada y centralizada.

📁 Categoría
Diagnóstico y soporte técnico

💻 Lenguaje
PowerShell (v5.1+)

📦 Dependencias
PsExec.exe (ubicación definida en $global:RutaPsExec)

Permisos de administración en los equipos remotos

Acceso a C$ para ejecución remota y lectura de resultados

Windows con .NET Framework (para WinForms)

🎯 Objetivo
Facilitar el análisis técnico de sistemas Windows mediante una herramienta todo-en-uno con análisis agrupados por áreas (Red, Sistema, Servicios, AD, DNS, Seguridad, etc.), y resultados visuales en tiempo real.

🖼️ Interfaz gráfica (GUI)
Formulario principal con diseño moderno, responsivo y claro (tipografía Segoe UI, fondo gris claro, botones planos).

Panel izquierdo: selección del equipo y árbol de análisis.

Panel derecho: resultados en tiempo real (RichTextBox con colores por nivel).

Validación automática del equipo introducido (local o remoto).

Botón para ejecutar análisis seleccionados.

Opción para guardar log en TXT.

🔧 Funciones destacadas
Diagnostico-Conectividad: ping interno/externo, IP, DNS, Gateway

Diagnostico-Rendimiento: uso de CPU/RAM, procesos top

Diagnostico-EstadoDominio: nombre de dominio, SID, PDC, etc.

Diagnostico-EventosCriticos: eventos 41, 6008, etc.

Diagnostico-DNSConfigurado: consulta a nslookup, resolución

Diagnostico-Actualizaciones: hotfix recientes, drivers, reinicio pendiente, actualizaciones pendientes

Diagnostico-CHKDSK/SFC/DISM: integridad del sistema de archivos

Diagnostico-ServiciosCriticos: verificación de WinRM, WMI, Netlogon...

Diagnostico-PostHang: análisis recientes tras cuelgue o reinicio

🗂️ Estructura del código
Organizado por bloques modulares con delimitadores visuales

Secciones: GUI, funciones de análisis, funciones auxiliares, eventos de GUI

Colores en log: verde (correcto), rojo (error), naranja (advertencia)

Salida exportable a archivo TXT con metadatos (fecha, equipo, etc.)

📌 Estado del proyecto
✅ Funcional
🧪 En uso para diagnóstico local y remoto en entorno real

📅 Última actualización
2025-03-29
