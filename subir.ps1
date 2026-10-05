# subir.ps1 - Copies the code and each board's config to the ESP32
# Usage: .\subir.ps1 alice                         Alice (COM5): code + config_alice.py
#        .\subir.ps1 bob                           Bob (COM7): code + config_bob.py
#        .\subir.ps1 ambas                         ambas = both boards
#        .\subir.ps1 ambas -Atacante               their packets go through the attacker PC (attacker.py)
#        .\subir.ps1 alice -Prueba protocol.py     also runs that test on the board
#                                                  (padding.py, aes_cbc.py, tag.py, hkdf.py, dh.py,
#                                                   protocol.py, medir.py or led.py)
# If the COM ports change, edit $PUERTOS.

param(
    [Parameter(Mandatory = $true)][ValidateSet("alice", "bob", "ambas")][string]$Placa,
    [switch]$Atacante,
    [string]$Prueba = ""
)

$PUERTOS = @{ alice = "COM5"; bob = "COM7" }
$comunes = "padding.py", "aes_cbc.py", "tag.py", "hkdf.py", "dh.py", "protocol.py", "medir.py"
$placa_archivos = "led.py", "main.py"

function Subir($nombre) {
    $puerto = $PUERTOS[$nombre]
    $cfg = "esp32/config_$nombre.py"
    Write-Host ""
    Write-Host "=== $nombre ($puerto) ==="
    if (-not (Test-Path $cfg)) {
        Write-Host "Missing $cfg (copy esp32/config_$nombre.example.py and fill it in)"
        return
    }

    Write-Host "Copying common/ and esp32/"
    python -m mpremote connect $puerto fs cp ($comunes | ForEach-Object { "common/$_" }) ($placa_archivos | ForEach-Object { "esp32/$_" }) :
    if ($LASTEXITCODE -ne 0) { Write-Host "Could not copy to $puerto"; return }

    # The config is copied with the name config.py. With -Atacante, USAR_ATACANTE = True is added
    $texto = [IO.File]::ReadAllText((Resolve-Path $cfg))
    if ($Atacante) { $texto += "`nUSAR_ATACANTE = True`n" }
    $tmp = Join-Path $env:TEMP "config.py"
    [IO.File]::WriteAllText($tmp, $texto, (New-Object Text.UTF8Encoding $false))   # no BOM
    python -m mpremote connect $puerto fs cp $tmp :config.py
    if ($Atacante) { Write-Host "Copied $cfg -> config.py (WITH attacker)" } else { Write-Host "Copied $cfg -> config.py (direct)" }
    Remove-Item $tmp

    if ($Prueba -ne "") {
        # run executes the file as __main__, so its test runs
        $archivo = if ($placa_archivos -contains $Prueba) { "esp32/$Prueba" } else { "common/$Prueba" }
        Write-Host "Running $archivo on $nombre"
        python -m mpremote connect $puerto run $archivo
    }
}

Push-Location $PSScriptRoot
try {
    if ($Placa -eq "ambas") { Subir "alice"; Subir "bob" } else { Subir $Placa }
}
finally {
    Pop-Location
}
