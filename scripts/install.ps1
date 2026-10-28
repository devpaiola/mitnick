param(
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'Programs\Mitnick')
)

$ErrorActionPreference = 'Stop'
$repository = 'mitnick-security/mitnick'
$baseUrl = "https://github.com/$repository/releases/latest/download"

if (-not $env:LOCALAPPDATA) {
    throw 'LOCALAPPDATA não está definido. Passe -InstallDir com um diretório de instalação.'
}

$architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
switch ($architecture) {
    'x64' { $goarch = 'amd64' }
    'arm64' { $goarch = 'arm64' }
    default { throw "Arquitetura não suportada: $architecture. Use x64 ou arm64." }
}

$archive = "mitnick_windows_${goarch}.tar.gz"
$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempDir | Out-Null

try {
    $archivePath = Join-Path $tempDir $archive
    $checksumsPath = Join-Path $tempDir 'SHA256SUMS'
    Invoke-WebRequest -Uri "$baseUrl/$archive" -OutFile $archivePath
    Invoke-WebRequest -Uri "$baseUrl/SHA256SUMS" -OutFile $checksumsPath

    $checksumLine = Get-Content $checksumsPath | Where-Object {
        $_ -match "^([0-9a-fA-F]{64})\s+\*?$([regex]::Escape($archive))$"
    } | Select-Object -First 1
    if (-not $checksumLine) {
        throw "SHA256SUMS não contém $archive."
    }
    $expectedHash = [regex]::Match($checksumLine, '^([0-9a-fA-F]{64})').Groups[1].Value.ToUpperInvariant()
    $actualHash = (Get-FileHash -Path $archivePath -Algorithm SHA256).Hash
    if ($actualHash -ne $expectedHash) {
        throw "Checksum inválido para $archive."
    }

    & tar.exe -xzf $archivePath -C $tempDir
    if ($LASTEXITCODE -ne 0) {
        throw "Não foi possível extrair $archive."
    }
    $binary = Get-ChildItem -Path $tempDir -Filter 'mitnick.exe' -File -Recurse |
        Where-Object { $_.Directory.Name -match "^mitnick_.+_windows_${goarch}$" } |
        Select-Object -First 1 -ExpandProperty FullName
    if (-not $binary) {
        throw 'O pacote não contém mitnick.exe no caminho esperado.'
    }

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Copy-Item -Path $binary -Destination (Join-Path $InstallDir 'mitnick.exe') -Force

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $pathEntries = @($userPath -split ';' | Where-Object { $_ })
    if ($pathEntries -notcontains $InstallDir) {
        $newPath = (@($pathEntries) + $InstallDir) -join ';'
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
    }
    if (($env:Path -split ';') -notcontains $InstallDir) {
        $env:Path = "$InstallDir;$env:Path"
    }

    Write-Host "Mitnick instalado em $InstallDir (windows/$goarch)."
    & (Join-Path $InstallDir 'mitnick.exe') version
    Write-Host 'O PATH do usuário foi atualizado. Novos terminais também encontrarão o comando mitnick.'
}
finally {
    Remove-Item -Path $tempDir -Recurse -Force
}
