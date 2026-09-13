param([string]$OutputPath)
$ErrorActionPreference='Stop'
if(!$OutputPath){$OutputPath=Join-Path $PSScriptRoot 'ClashConfigAssistant.exe'}
$taskCompiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$taskLib=Join-Path $PSScriptRoot 'yaml-lib\lib\net47\YamlDotNet.dll'
$taskProbe=Join-Path $PSScriptRoot 'ClashGuardProbe.exe'
& $taskCompiler /nologo /target:exe /platform:x64 /optimize+ "/out:$taskProbe" (Join-Path $PSScriptRoot 'Probe.cs')
if($LASTEXITCODE -ne 0){throw 'Probe compilation failed'}
& $taskCompiler /nologo /target:winexe /platform:x64 /optimize+ /codepage:65001 "/win32icon:$PSScriptRoot\app.ico" "/resource:$PSScriptRoot\app.ico,app.ico" "/win32manifest:$PSScriptRoot\app.manifest" /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll /reference:System.Security.dll "/reference:$taskLib" "/resource:$taskLib,YamlDotNet.dll" "/resource:$taskProbe,ClashGuardProbe.exe" "/out:$OutputPath" (Join-Path $PSScriptRoot 'App.cs') (Join-Path $PSScriptRoot 'Core.cs') (Join-Path $PSScriptRoot 'Guard.cs') (Join-Path $PSScriptRoot 'Tests.cs') (Join-Path $PSScriptRoot 'Memory.cs') (Join-Path $PSScriptRoot 'Mode2.cs')
if($LASTEXITCODE -ne 0){throw 'Application compilation failed'}
Get-FileHash $OutputPath
