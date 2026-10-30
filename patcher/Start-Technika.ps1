param([ValidateRange(0,900)][int]$VerifySeconds=0)
$ErrorActionPreference='Stop'
$workspacePath=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$gamePath=Join-Path $workspacePath 'Client.exe'
$logPath=Join-Path $PSScriptRoot 'last-run.json'
$prefix='launch-current'
$ownedProcess=$null
$keepRunning=$false
$mutex=$null
$mutexHeld=$false
$exitStatus=1
$report=[ordered]@{startedUTC=[DateTime]::UtcNow.ToString('o');state='starting';gamePath=$gamePath;processId=$null;verifySeconds=$VerifySeconds;patches=@();windows=@();error=$null}
function Save-LaunchReport {
 $report.updatedUTC=[DateTime]::UtcNow.ToString('o')
 $report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $logPath -Encoding UTF8
}
function Read-PeriodicCheckCount {
 $record=Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot "$prefix-periodic-key-patch.json") | ConvertFrom-Json
 if($record.processId -ne $ownedProcess.Id){throw 'Periodic key-check record belongs to a different process.'}
 $handle=[TechnikaNormalCapture]::OpenProcess(0x410,$false,$ownedProcess.Id)
 if($handle -eq [IntPtr]::Zero){throw 'Cannot verify periodic key-check counter.'}
 try{
  $bytes=New-Object byte[] 4;$read=[UIntPtr]::Zero
  if(![TechnikaNormalCapture]::ReadProcessMemory($handle,[IntPtr]([long]$record.counterAddress),$bytes,[UIntPtr]([uint32]4),[ref]$read) -or $read.ToUInt64() -ne 4){throw 'Cannot read periodic key-check counter.'}
  return [BitConverter]::ToUInt32($bytes,0)
 }finally{[void][TechnikaNormalCapture]::CloseHandle($handle)}
}
function Read-WatcherState {
 $record=Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot "$prefix-watcher-patch.json") | ConvertFrom-Json
 if($record.processId -ne $ownedProcess.Id){throw 'Watcher patch record belongs to a different process.'}
 $handle=[TechnikaNormalCapture]::OpenProcess(0x410,$false,$ownedProcess.Id)
 if($handle -eq [IntPtr]::Zero){throw 'Cannot verify Watcher timeout patch.'}
 try{
  $bytes=New-Object byte[] 8;$read=[UIntPtr]::Zero
  if(![TechnikaNormalCapture]::ReadProcessMemory($handle,[IntPtr]([long]$record.counterAddress),$bytes,[UIntPtr]([uint32]8),[ref]$read) -or $read.ToUInt64() -ne 8){throw 'Cannot read Watcher timeout counter.'}
  $result=[ordered]@{ignoredTimeouts=[BitConverter]::ToUInt32($bytes,0);objectAddress=[BitConverter]::ToUInt32($bytes,4);elapsedMs=$null;limitMs=$null}
  if($result.objectAddress){
   $timer=New-Object byte[] 8
   if(![TechnikaNormalCapture]::ReadProcessMemory($handle,[IntPtr]([long]$result.objectAddress+8),$timer,[UIntPtr]([uint32]8),[ref]$read) -or $read.ToUInt64() -ne 8){throw 'Cannot read Watcher timer.'}
   $result.elapsedMs=[BitConverter]::ToUInt32($timer,0);$result.limitMs=[BitConverter]::ToUInt32($timer,4)
  }
  return [pscustomobject]$result
 }finally{[void][TechnikaNormalCapture]::CloseHandle($handle)}
}
try {
 $identity=(Get-FileHash -LiteralPath $gamePath -Algorithm SHA256).Hash.ToLowerInvariant()
 $report.sourceSHA256=$identity
 if($identity -ne '9f7ec04c6abc9542e247dbe33bec3f8f472b885047e69d970650f7b7d5565925'){throw 'Client.exe does not match the supported original version. Restore the original file before using this launcher.'}
 $gameSettings=Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'game-settings.json') | ConvertFrom-Json
 if($gameSettings.freePlay -isnot [bool]){throw 'game-settings.json freePlay must be true or false.'}
 $freePlay=[bool]$gameSettings.freePlay
 $report.freePlay=$freePlay
 $engineFiles=Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'engine-files.json') | ConvertFrom-Json
 foreach($file in $engineFiles.PSObject.Properties){
  if($file.Name -notmatch '^[A-Za-z0-9.-]+$'){throw 'Invalid engine manifest'}
  $actual=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $file.Name) -Algorithm SHA256).Hash
  if($actual -ne $file.Value){throw "Launcher engine file changed: $($file.Name)"}
 }
 $pathBytes=[Text.Encoding]::UTF8.GetBytes($workspacePath.ToLowerInvariant())
 $pathHash=[Security.Cryptography.SHA256]::Create()
 try{$mutexSuffix=([BitConverter]::ToString($pathHash.ComputeHash($pathBytes))).Replace('-','')}finally{$pathHash.Dispose()}
 $mutex=New-Object Threading.Mutex($false,"Local\TechnikaStartup-$mutexSuffix")
 try{$mutexHeld=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$mutexHeld=$true}
 if(!$mutexHeld){throw 'Another launch is already in progress.'}
 Add-Type -Path (Join-Path $PSScriptRoot 'TechnikaInterop.cs')
 foreach($existing in @(Get-Process -Name Client -ErrorAction SilentlyContinue)){
  $existingPath=$null
  try{$existingPath=$existing.MainModule.FileName}catch{}
  if($existingPath -eq $gamePath){throw 'This game is already running. Close that instance before starting another.'}
 }
 $report.state='waiting-for-key-check'
 Save-LaunchReport
 # The game is the intended interactive application. The launcher helper is hidden.
 $ownedProcess=Start-Process -FilePath $gamePath -WorkingDirectory $workspacePath -PassThru
 $report.processId=$ownedProcess.Id
 $dialog=$null
 $deadline=[DateTime]::UtcNow.AddSeconds(20)
 while([DateTime]::UtcNow -lt $deadline){
  if($ownedProcess.HasExited){throw 'Client exited before the supported key-check stage.'}
  $windows=@([TechnikaNormalCapture]::Windows($ownedProcess.Id))
  $unexpected=$windows | Where-Object {($_.children -join ' ') -match 'Error loading program|Sentinel'} | Select-Object -First 1
  if($unexpected){throw ('Unsupported startup error: '+($unexpected.children -join ' '))}
  $dialog=$windows | Where-Object {($_.children -join ' ') -match 'No Correct Hardware Dog Found'} | Select-Object -First 1
  if($dialog -and @($dialog.controls | Where-Object {$_.className -eq 'Button'}).Count -gt 0){break}
  Start-Sleep -Milliseconds 100
 }
 if(!$dialog){throw 'The expected key-check stage was not reached within 20 seconds.'}
 [pscustomobject]@{scope='Owned launcher process';processId=$ownedProcess.Id;windows=$windows} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $PSScriptRoot "$prefix-dialog.json") -Encoding UTF8
 $report.state='applying-runtime-patches'
 Save-LaunchReport
 & (Join-Path $PSScriptRoot 'apply-runtime-patch.ps1') -TargetProcessId $ownedProcess.Id -Prefix $prefix -Experiment 'skip-dog-checks' -PauseLastLayer -PatchBody -FixAdapterBuffer -FixPeriodicKeyCheck -FixWatcherTimeout -EnableFreePlay:$freePlay -CompactMode
 $outcome=Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot "$prefix-after-force.json") | ConvertFrom-Json
 $report.windows=$outcome.windows
 if($ownedProcess.HasExited){throw 'The game exited during initialization.'}
 $blocking=$outcome.windows | Where-Object {($_.title+' '+($_.children -join ' ')) -match 'Runtime Error|Error loading|Hardware Dog|Sentinel'} | Select-Object -First 1
 if($blocking){throw ('Game initialization failed: '+$blocking.title+' '+($blocking.children -join ' '))}
 if(!@($outcome.windows | Where-Object {$_.title -eq 'ClientApp'}).Count){throw 'The patches were applied, but the game window did not appear.'}
 $report.patches=@('shell key-check continuation after exact byte checks','body validation success after final loader stage','real adapter buffer enlarged from 648 to 65536 bytes')
 $report.patches+=@('runtime shell watchdog key-check success with invocation counter')
 $report.patches+=@('Watcher1 heartbeat timeout fatal branch bypass with expired-timer counter')
 if($freePlay){$report.patches+=@('native free-play mode for display, start eligibility and debit')}
 $report.state='game-window-running'
 $report.periodicKeyCheckCalls=Read-PeriodicCheckCount
 $report.watcher=Read-WatcherState
 Save-LaunchReport
 if($VerifySeconds -gt 0){
  $verifyDeadline=[DateTime]::UtcNow.AddSeconds($VerifySeconds)
  $nextCheckpoint=[DateTime]::UtcNow.AddSeconds(30)
  while([DateTime]::UtcNow -lt $verifyDeadline){
   if($ownedProcess.HasExited){throw 'The game exited during the verification interval.'}
   if([DateTime]::UtcNow -ge $nextCheckpoint){
    $report.periodicKeyCheckCalls=Read-PeriodicCheckCount
    $report.watcher=Read-WatcherState
    $report.windows=@([TechnikaNormalCapture]::Windows($ownedProcess.Id))
    $checkpointError=$report.windows | Where-Object {($_.title+' '+($_.children -join ' ')) -match 'Runtime Error|Error loading|Hardware Dog|Sentinel|Could not open the driver'} | Select-Object -First 1
    if($checkpointError){throw ('Error appeared during verification: '+$checkpointError.title+' '+($checkpointError.children -join ' '))}
    Save-LaunchReport
    $nextCheckpoint=[DateTime]::UtcNow.AddSeconds(30)
   }
   Start-Sleep -Milliseconds 250
  }
  $report.windows=@([TechnikaNormalCapture]::Windows($ownedProcess.Id))
  $verificationError=$report.windows | Where-Object {($_.title+' '+($_.children -join ' ')) -match 'Runtime Error|Error loading|Hardware Dog|Sentinel'} | Select-Object -First 1
  if($verificationError){throw ('Error appeared during verification: '+$verificationError.title+' '+($verificationError.children -join ' '))}
  if(!@($report.windows | Where-Object {$_.title -eq 'ClientApp'}).Count){throw 'The game window disappeared during verification.'}
  $report.periodicKeyCheckCalls=Read-PeriodicCheckCount
  $report.watcher=Read-WatcherState
  if($VerifySeconds -ge 180 -and $report.periodicKeyCheckCalls -lt 1){throw 'The verification interval ended without exercising the periodic key-check patch.'}
  if($VerifySeconds -ge 620 -and ($report.watcher.ignoredTimeouts -lt 1 -or $report.watcher.limitMs -ne 600000 -or $report.watcher.elapsedMs -le 600000)){throw 'The verification interval did not exercise the original ten-minute Watcher timeout.'}
  $report.state='verification-passed'
 }else{
  $keepRunning=$true
  $report.state='started-game-left-running'
 }
 $exitStatus=0
}catch{
 $report.state='failed'
 $report.error=$_.Exception.Message
 if($ownedProcess -and !$ownedProcess.HasExited){$ownedProcess.Kill();[void]$ownedProcess.WaitForExit(3000)}
 if($VerifySeconds -eq 0){
  try{
   Add-Type -AssemblyName System.Windows.Forms
   [void][Windows.Forms.MessageBox]::Show("TECHNIKA 启动失败。`r`n$($report.error)`r`n`r`n详情：$logPath",'TECHNIKA')
  }catch{}
 }
}finally{
 if($ownedProcess -and !$keepRunning -and !$ownedProcess.HasExited){$ownedProcess.Kill();[void]$ownedProcess.WaitForExit(3000)}
 if($ownedProcess){$report.ownedProcessLeftRunning=(!$ownedProcess.HasExited)}
 if($ownedProcess -and $ownedProcess.HasExited){$report.gameExitCode=$ownedProcess.ExitCode}
 $report.originalFileUnchanged=((Get-FileHash -LiteralPath $gamePath -Algorithm SHA256).Hash.ToLowerInvariant() -eq '9f7ec04c6abc9542e247dbe33bec3f8f472b885047e69d970650f7b7d5565925')
 if($mutexHeld){$mutex.ReleaseMutex()}
 if($mutex){$mutex.Dispose()}
 Save-LaunchReport
}
exit $exitStatus
