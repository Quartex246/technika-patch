$ErrorActionPreference='Stop'
$rootPath=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe'
$outputPath=Join-Path $rootPath 'Start-Technika.exe'
& $compiler /nologo /target:winexe /platform:anycpu /optimize+ /codepage:65001 /reference:System.Windows.Forms.dll "/out:$outputPath" (Join-Path $PSScriptRoot 'TechnikaLauncher.cs')
if($LASTEXITCODE -ne 0){throw 'Launcher compilation failed'}
