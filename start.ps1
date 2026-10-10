$ErrorActionPreference = 'Stop'
$executable = Join-Path $PSScriptRoot 'nodepure.exe'
if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
    throw 'Build first: go build -trimpath -o nodepure.exe ./cmd/server'
}
# An explicit private working directory also supports Windows policies that deny TEMP.
if (-not $env:NODEPURE_TEMP_DIR) {
    $tempRoot = Join-Path $PSScriptRoot '.nodepure-tmp'
    if (-not (Test-Path -LiteralPath $tempRoot)) {
        New-Item -ItemType Directory -Path $tempRoot | Out-Null
        $acl = Get-Acl -LiteralPath $tempRoot
        $acl.SetAccessRuleProtection($true, $false)
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        $inheritance = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $identity, 'FullControl', $inheritance,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
        Set-Acl -LiteralPath $tempRoot -AclObject $acl
    }
    $env:NODEPURE_TEMP_DIR = $tempRoot
}
if (-not $env:MIHOMO_BIN) {
    $env:MIHOMO_BIN = Join-Path $PSScriptRoot 'bin/mihomo.exe'
}
Push-Location -LiteralPath $PSScriptRoot
try {
    & $executable
    if ($LASTEXITCODE -ne 0) { throw "NodePure exited with code $LASTEXITCODE" }
} finally {
    Pop-Location
}
