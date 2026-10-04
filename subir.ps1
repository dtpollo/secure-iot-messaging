# subir.ps1 - Copia los modulos de common/ a la raiz de la ESP32 y corre la prueba de protocol.py
# Uso:  .\subir.ps1           (usa COM5)
#       .\subir.ps1 COM3      (otro puerto)

param([string]$Puerto = "COM5")

$modulos = "padding.py", "aes_cbc.py", "tag.py", "hkdf.py", "dh.py", "protocol.py"

Push-Location (Join-Path $PSScriptRoot "common")
try {
    Write-Host "Copiando a la ESP32 ($Puerto): $modulos"
    mpremote connect $Puerto fs cp @modulos :
    if ($LASTEXITCODE -ne 0) { Write-Host "No se pudo copiar"; exit 1 }

    Write-Host "Corriendo la prueba de protocol.py"
    mpremote connect $Puerto run protocol.py
}
finally {
    Pop-Location
}
