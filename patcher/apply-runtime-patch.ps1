param([int]$TargetProcessId,[string]$Prefix,[ValidateSet('force-zero','skip-dog-checks')][string]$Experiment='force-zero',[switch]$PauseLastLayer,[switch]$PatchBody,[switch]$FixAdapterBuffer,[switch]$FixPeriodicKeyCheck,[switch]$FixWatcherTimeout,[switch]$EnableFreePlay,[switch]$CompactMode)
$ErrorActionPreference='Stop'
if($PatchBody -and (!$PauseLastLayer -or $Experiment -ne 'skip-dog-checks')){throw 'Body test requires the last-layer halt'}
if($FixAdapterBuffer -and !$PatchBody){throw 'Adapter compatibility experiment requires the controlled body patch stage'}
if($EnableFreePlay -and !$PatchBody){throw 'Free Play requires the verified final loader stage'}
if($FixPeriodicKeyCheck -and !$PatchBody){throw 'Periodic key-check compatibility requires the verified final loader stage'}
if($FixWatcherTimeout -and !$PatchBody){throw 'Watcher compatibility requires the verified final loader stage'}
$workspacePath=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$targetProcess=Get-Process -Id $TargetProcessId
if($targetProcess.MainModule.FileName -ne (Join-Path $workspacePath 'Client.exe')){throw 'Wrong target path'}
$dialogRecord=Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot "$Prefix-dialog.json") | ConvertFrom-Json
$dialog=$dialogRecord.windows | Where-Object {($_.children -join ' ') -match 'No Correct Hardware Dog Found'} | Select-Object -First 1
if(!$dialog){throw 'Expected normal-launch key error was not observed'}
if(-not ('TechnikaNormalCapture' -as [type])){throw 'Interop must be initialized by Start-Technika.ps1'}
$processHandle=[TechnikaNormalCapture]::OpenProcess(0x438,$false,$TargetProcessId)
if($processHandle -eq [IntPtr]::Zero){throw 'Cannot open controlled Client process'}
$dialogThread=[TechnikaNormalCapture]::OpenThread(0x40,$false,[int]$dialog.thread)
if($dialogThread -eq [IntPtr]::Zero){[void][TechnikaNormalCapture]::CloseHandle($processHandle);throw 'Cannot hold dialog thread for outcome query'}
$vmTraces=@()
function Write-TargetBytes([long]$address,[byte[]]$bytes){
 $written=[UIntPtr]::Zero
 if(![TechnikaNormalCapture]::WriteProcessMemory($processHandle,[IntPtr]$address,$bytes,[UIntPtr]([uint32]$bytes.Length),[ref]$written) -or $written.ToUInt64() -ne $bytes.Length){throw "Target write failed at $address"}
}
try {
 $returnSite=[uint32]0xF2C01FF
 $original=New-Object byte[] 5
 $read=[UIntPtr]::Zero
 if(![TechnikaNormalCapture]::ReadProcessMemory($processHandle,[IntPtr]([long]$returnSite),$original,[UIntPtr]([uint32]5),[ref]$read)){throw 'Cannot read return site'}
 if([BitConverter]::ToString($original) -ne 'B9-14-00-00-00'){throw 'Unexpected return-site bytes; no patch applied'}
 $trampoline=[TechnikaNormalCapture]::VirtualAllocEx($processHandle,[IntPtr]::Zero,[UIntPtr]([uint32]65536),0x3000,0x40)
 if($trampoline -eq [IntPtr]::Zero -or $trampoline.ToInt64() -gt [uint32]::MaxValue){throw 'Cannot allocate a 32-bit trampoline'}
 if($Experiment -eq 'skip-dog-checks'){
  $layers=Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'vm-trace-layers.json') | ConvertFrom-Json
  if($layers.Count -lt 1 -or $layers.Count -gt 32){throw 'Invalid VM trace layer count'}
  $childHook=$null
  for($layerIndex=$layers.Count-1;$layerIndex -ge 0;$layerIndex--){
   $layer=$layers[$layerIndex]
   $stopIp=[uint32]0
   $stopIp2=[uint32]0
   $triggerIp2=[uint32]0
   if($layer.alternateTerminal){$triggerIp2=[Convert]::ToUInt32($layer.alternateTerminal.Substring(2),16)}
   if($PauseLastLayer -and $layerIndex -eq ($layers.Count-1)){$stopIp=[Convert]::ToUInt32($layer.terminal.Substring(2),16)}
   if($stopIp){$stopIp2=$triggerIp2}
   $childHook=& (Join-Path $PSScriptRoot 'install-vm-trace.ps1') -ProcessHandle $processHandle -CodeAddress ($trampoline.ToInt64()+0x200+0x400*$layerIndex) -HookAddress ([Convert]::ToInt64($layer.loop.Substring(2),16)) -IpGlobal ([Convert]::ToUInt32($layer.ip.Substring(2),16)) -SpGlobal ([Convert]::ToUInt32($layer.sp.Substring(2),16)) -CommandGlobal ([Convert]::ToUInt32($layer.command.Substring(2),16)) -HookNow ($layerIndex -eq 0) -FollowupHook $childHook -TriggerIp ([Convert]::ToUInt32($layer.terminal.Substring(2),16)) -TriggerIp2 $triggerIp2 -StopIp $stopIp -StopIp2 $stopIp2
   $vmTraces=@($childHook)+$vmTraces
  }
 }
 $code=New-Object 'System.Collections.Generic.List[byte]'
 # Restore the five original return-site bytes immediately on first execution.
 $code.AddRange([byte[]]@(0xC7,0x05));$code.AddRange([BitConverter]::GetBytes($returnSite));$code.AddRange([byte[]]@(0xB9,0x14,0,0))
 $code.AddRange([byte[]]@(0xC6,0x05));$code.AddRange([BitConverter]::GetBytes([uint32]($returnSite+4)));$code.Add(0)
 # Set the command operand to zero and restore the resolver argument used by
 # the normal success path; caller EBP/ESP are restored by MessageBox itself.
 if($Experiment -eq 'force-zero'){
  $code.AddRange([byte[]]@(0x66,0xC7,0x05));$code.AddRange([BitConverter]::GetBytes([uint32]0xF2B5E1A));$code.AddRange([byte[]]@(0,0,0x8B,0x75,0x0C,0x33,0xFF))
  $resumeAddress=[long]0xF2BFE03
 }else{
  # Continue the saved VM after its two failure branches, retaining the observed
  # empty VM stack. This deliberately omits their outputs and is a dependency test.
  $code.AddRange([byte[]]@(0xC7,0x05));$code.AddRange([BitConverter]::GetBytes([uint32]0xF2B112C));$code.AddRange([BitConverter]::GetBytes([uint32]0xF2B1510))
  $code.AddRange([byte[]]@(0x8B,0x75,0x0C,0xBF,0x0A,0,0,0,0xBB,0x04,0,0,0))
  $resumeAddress=[long]0xF2BEE01
 }
 $code.Add(0xE9)
 $jumpDelta=[int32]($resumeAddress-$trampoline.ToInt64()-$code.Count-4)
 $code.AddRange([BitConverter]::GetBytes($jumpDelta))
 Write-TargetBytes $trampoline.ToInt64() $code.ToArray()
 $oldProtection=[uint32]0
 if(![TechnikaNormalCapture]::VirtualProtectEx($processHandle,[IntPtr]([long]$returnSite),[UIntPtr]([uint32]5),0x40,[ref]$oldProtection)){throw 'Cannot write controlled return site'}
 $redirect=New-Object byte[] 5
 $redirect[0]=0xE9
 [BitConverter]::GetBytes([int32]($trampoline.ToInt64()-$returnSite-5)).CopyTo($redirect,1)
 Write-TargetBytes $returnSite $redirect
 [void][TechnikaNormalCapture]::FlushInstructionCache($processHandle,[IntPtr]::Zero,[UIntPtr]::Zero)
 $patchRecord=[ordered]@{status='runtime-experiment-not-a-file-patch';experiment=$Experiment;processId=$TargetProcessId;returnSite=('0x{0:x}' -f $returnSite);trampoline=('0x{0:x}' -f $trampoline.ToInt64());originalBytes=[BitConverter]::ToString($original);temporaryRedirect=[BitConverter]::ToString($redirect);trampolineBytes=[BitConverter]::ToString($code.ToArray());previousProtection=$oldProtection}
 $patchRecord | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $PSScriptRoot "$Prefix-runtime-patch.json") -Encoding UTF8
 $dialogHandle=[IntPtr]([long]$dialog.handle)
 $buttonRecord=$dialog.controls | Where-Object {$_.className -eq 'Button'} | Select-Object -First 1
 if(!$buttonRecord){throw 'Cannot find the controlled dialog button'}
 $button=[IntPtr]([long]$buttonRecord.handle)
 # MessageBox may change its sole button from IDOK to IDCANCEL after creation.
 # Query the live control after memory capture instead of reusing the earlier ID.
 $liveButtonId=[TechnikaNormalCapture]::GetDlgCtrlID($button)
 $messageResult=[UIntPtr]::Zero
 $messageCall=[TechnikaNormalCapture]::SendMessageTimeout($dialogHandle,0x111,[UIntPtr]([uint32]$liveButtonId),$button,2,2000,[ref]$messageResult)
 [pscustomobject]@{dialog=$dialog.handle;button=$button.ToInt64();buttonId=$liveButtonId;sendResult=$messageCall.ToInt64();messageResult=$messageResult.ToUInt64();lastError=[Runtime.InteropServices.Marshal]::GetLastWin32Error()} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $PSScriptRoot "$Prefix-dismiss.json") -Encoding UTF8
 if($CompactMode){
  $haltDeadline=[DateTime]::UtcNow.AddSeconds(20)
  while([Runtime.InteropServices.Marshal]::ReadInt32($vmTraces[-1].local,8) -ne 1){
   if($targetProcess.HasExited){throw 'Game exited before final loader stage'}
   if([DateTime]::UtcNow -ge $haltDeadline){throw 'Final loader stage timed out'}
   Start-Sleep -Milliseconds 20
  }
 }else{Start-Sleep -Seconds 3}
 if($PatchBody){
  $lastTrace=$vmTraces[-1]
  if([Runtime.InteropServices.Marshal]::ReadInt32($lastTrace.local,8) -ne 1 -or $layers[-1].terminal -ne '0xF484C18'){throw 'The verified final loader halt was not reached; no body patch'}
  $verifyAddress=[long]0x618790
  $verifyOriginal=New-Object byte[] 6;$verifyRead=[UIntPtr]::Zero
  if(![TechnikaNormalCapture]::ReadProcessMemory($processHandle,[IntPtr]$verifyAddress,$verifyOriginal,[UIntPtr]([uint32]6),[ref]$verifyRead) -or [BitConverter]::ToString($verifyOriginal) -ne '55-8B-EC-83-EC-54'){throw 'Decrypted body verification bytes differ; no body patch'}
  $verifyProtect=[uint32]0
  if(![TechnikaNormalCapture]::VirtualProtectEx($processHandle,[IntPtr]$verifyAddress,[UIntPtr]([uint32]6),0x40,[ref]$verifyProtect)){throw 'Cannot change owned verification page protection'}
  $verifyReplacement=[byte[]]@(0xB8,1,0,0,0,0xC3)
  Write-TargetBytes $verifyAddress $verifyReplacement
  if(![TechnikaNormalCapture]::FlushInstructionCache($processHandle,[IntPtr]$verifyAddress,[UIntPtr]([uint32]6))){throw 'Body instruction cache flush failed'}
  $discardProtect=[uint32]0
  if(![TechnikaNormalCapture]::VirtualProtectEx($processHandle,[IntPtr]$verifyAddress,[UIntPtr]([uint32]6),$verifyProtect,[ref]$discardProtect)){throw 'Cannot restore body page protection'}
  [pscustomobject]@{scope='Runtime-only body verification experiment after final loader terminal';address='0x618790';original=[BitConverter]::ToString($verifyOriginal);replacement=[BitConverter]::ToString($verifyReplacement);previousProtection=$verifyProtect;deviceIdentifier='left at default zero; no invented dongle output'} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $PSScriptRoot "$Prefix-body-patch.json") -Encoding UTF8
  if($FixAdapterBuffer){
   $adapterChanges=@()
   foreach($sizeAddress in @([long]0x5A87B0,[long]0x5A87C9)){
    $oldSize=New-Object byte[] 4;$sizeRead=[UIntPtr]::Zero
    if(![TechnikaNormalCapture]::ReadProcessMemory($processHandle,[IntPtr]$sizeAddress,$oldSize,[UIntPtr]([uint32]4),[ref]$sizeRead) -or [BitConverter]::ToUInt32($oldSize,0) -ne 648){throw 'Adapter buffer immediate mismatch; refusing compatibility patch'}
    $sizeProtect=[uint32]0
    if(![TechnikaNormalCapture]::VirtualProtectEx($processHandle,[IntPtr]$sizeAddress,[UIntPtr]([uint32]4),0x40,[ref]$sizeProtect)){throw 'Cannot change adapter code page protection'}
    Write-TargetBytes $sizeAddress ([BitConverter]::GetBytes([uint32]65536))
    if(![TechnikaNormalCapture]::FlushInstructionCache($processHandle,[IntPtr]$sizeAddress,[UIntPtr]([uint32]4))){throw 'Adapter instruction cache flush failed'}
    $sizeDiscard=[uint32]0
    if(![TechnikaNormalCapture]::VirtualProtectEx($processHandle,[IntPtr]$sizeAddress,[UIntPtr]([uint32]4),$sizeProtect,[ref]$sizeDiscard)){throw 'Cannot restore adapter code page protection'}
    $adapterChanges += [pscustomobject]@{address=('0x{0:x}' -f $sizeAddress);oldBytes=648;newBytes=65536;previousProtection=$sizeProtect}
   }
   [pscustomobject]@{scope='Use a larger real GetAdaptersInfo buffer; no MAC or network identity is fabricated';changes=$adapterChanges} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $PSScriptRoot "$Prefix-adapter-patch.json") -Encoding UTF8
  }
  if($FixPeriodicKeyCheck){
   # The shell watchdog calls this no-argument status function at 0xF2BA19D
   # and 0xF2BA1C9. Zero takes its normal continue-running branch. Keep the
   # watchdog's event/wait/cleanup loop intact and count actual invocations.
   $periodicAddress=[long]0xF2C2D20
   $periodicOriginal=New-Object byte[] 6;$periodicRead=[UIntPtr]::Zero
   if(![TechnikaNormalCapture]::ReadProcessMemory($processHandle,[IntPtr]$periodicAddress,$periodicOriginal,[UIntPtr]([uint32]6),[ref]$periodicRead) -or [BitConverter]::ToString($periodicOriginal) -ne '55-8B-EC-83-EC-10'){throw 'Periodic key-check bytes differ; refusing runtime patch'}
   $periodicStub=$trampoline.ToInt64()+0x8000
   $periodicCounter=$trampoline.ToInt64()+0x8100
   $periodicCode=[byte[]]@(0xFF,0x05)+[BitConverter]::GetBytes([uint32]$periodicCounter)+[byte[]]@(0x33,0xC0,0xC3)
   Write-TargetBytes $periodicCounter ([byte[]]@(0,0,0,0))
   Write-TargetBytes $periodicStub $periodicCode
   $periodicReplacement=[byte[]]@(0xE9)+[BitConverter]::GetBytes([int32]($periodicStub-$periodicAddress-5))+[byte[]]@(0x90)
   $periodicProtect=[uint32]0
   if(![TechnikaNormalCapture]::VirtualProtectEx($processHandle,[IntPtr]$periodicAddress,[UIntPtr]([uint32]6),0x40,[ref]$periodicProtect)){throw 'Cannot change periodic key-check page protection'}
   Write-TargetBytes $periodicAddress $periodicReplacement
   if(![TechnikaNormalCapture]::FlushInstructionCache($processHandle,[IntPtr]::Zero,[UIntPtr]::Zero)){throw 'Periodic key-check instruction cache flush failed'}
   $periodicDiscard=[uint32]0
   if(![TechnikaNormalCapture]::VirtualProtectEx($processHandle,[IntPtr]$periodicAddress,[UIntPtr]([uint32]6),$periodicProtect,[ref]$periodicDiscard)){throw 'Cannot restore periodic key-check page protection'}
   [pscustomobject]@{processId=$TargetProcessId;scope='Runtime shell watchdog key-check returns its success status; wait/event lifecycle retained';address='0xF2C2D20';original=[BitConverter]::ToString($periodicOriginal);replacement=[BitConverter]::ToString($periodicReplacement);stubAddress=$periodicStub;stubBytes=[BitConverter]::ToString($periodicCode);counterAddress=$periodicCounter;previousProtection=$periodicProtect} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $PSScriptRoot "$Prefix-periodic-key-patch.json") -Encoding UTF8
  }
  if($FixWatcherTimeout){
   # Only replace the Watcher1 timeout decision. Preserve clipboard handling,
   # timer updates, EDX, EAX and the decision flags; retain all other errors.
   $watcherAddress=[long]0x617FEA
   $watcherOriginal=New-Object byte[] 7;$watcherRead=[UIntPtr]::Zero
   if(![TechnikaNormalCapture]::ReadProcessMemory($processHandle,[IntPtr]$watcherAddress,$watcherOriginal,[UIntPtr]([uint32]7),[ref]$watcherRead) -or [BitConverter]::ToString($watcherOriginal) -ne '0F-B6-D0-85-D2-75-1C'){throw 'Watcher timeout decision bytes differ; refusing runtime patch'}
   $watcherStub=$trampoline.ToInt64()+0x8200
   $watcherCounter=$trampoline.ToInt64()+0x8300
   $watcherObjectSlot=$watcherCounter+4
   # Save the current object for read-only timer verification. Then emulate
   # MOVZX EDX,AL / TEST EDX,EDX and count only actual expired-timer results.
   $watcherCode=[byte[]]@(0x50,0x8B,0x45,0xFC,0xA3)+[BitConverter]::GetBytes([uint32]$watcherObjectSlot)+[byte[]]@(0x58,0x0F,0xB6,0xD0,0x85,0xD2,0x75,0x08,0x9C,0xFF,0x05)+[BitConverter]::GetBytes([uint32]$watcherCounter)+[byte[]]@(0x9D,0xE9)
   $watcherCode+=[BitConverter]::GetBytes([int32](0x61800D-$watcherStub-$watcherCode.Length-4))
   Write-TargetBytes $watcherCounter ([byte[]]@(0,0,0,0,0,0,0,0))
   Write-TargetBytes $watcherStub $watcherCode
   $watcherReplacement=[byte[]]@(0xE9)+[BitConverter]::GetBytes([int32]($watcherStub-$watcherAddress-5))+[byte[]]@(0x90,0x90)
   $watcherProtect=[uint32]0
   if(![TechnikaNormalCapture]::VirtualProtectEx($processHandle,[IntPtr]$watcherAddress,[UIntPtr]([uint32]7),0x40,[ref]$watcherProtect)){throw 'Cannot change Watcher code protection'}
   Write-TargetBytes $watcherAddress $watcherReplacement
   if(![TechnikaNormalCapture]::FlushInstructionCache($processHandle,[IntPtr]::Zero,[UIntPtr]::Zero)){throw 'Watcher instruction cache flush failed'}
   $watcherDiscard=[uint32]0
   if(![TechnikaNormalCapture]::VirtualProtectEx($processHandle,[IntPtr]$watcherAddress,[UIntPtr]([uint32]7),$watcherProtect,[ref]$watcherDiscard)){throw 'Cannot restore Watcher code protection'}
   [pscustomobject]@{processId=$TargetProcessId;scope='Only bypass Watcher1 heartbeat timeout fatal branch (code 13); original 600000ms timer retained';address='0x617FEA';original=[BitConverter]::ToString($watcherOriginal);replacement=[BitConverter]::ToString($watcherReplacement);stubAddress=$watcherStub;stubBytes=[BitConverter]::ToString($watcherCode);counterAddress=$watcherCounter;objectSlot=$watcherObjectSlot;resumeAddress='0x61800D';previousProtection=$watcherProtect} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $PSScriptRoot "$Prefix-watcher-patch.json") -Encoding UTF8
  }
  if($EnableFreePlay){
   # Native mode getter: mode 1 selects the built-in FREE PLAY display and
   # makes both credit availability and debit operations succeed without debit.
   $modeAddress=[long]0x412370
   $modeOriginal=New-Object byte[] 6;$modeRead=[UIntPtr]::Zero
   if(![TechnikaNormalCapture]::ReadProcessMemory($processHandle,[IntPtr]$modeAddress,$modeOriginal,[UIntPtr]([uint32]6),[ref]$modeRead) -or [BitConverter]::ToString($modeOriginal) -ne '55-8B-EC-51-89-4D'){throw 'Native game-mode getter bytes differ; refusing Free Play patch'}
   $modeProtect=[uint32]0
   if(![TechnikaNormalCapture]::VirtualProtectEx($processHandle,[IntPtr]$modeAddress,[UIntPtr]([uint32]6),0x40,[ref]$modeProtect)){throw 'Cannot change game-mode code page protection'}
   $modeReplacement=[byte[]]@(0xB8,1,0,0,0,0xC3)
   Write-TargetBytes $modeAddress $modeReplacement
   if(![TechnikaNormalCapture]::FlushInstructionCache($processHandle,[IntPtr]$modeAddress,[UIntPtr]([uint32]6))){throw 'Game-mode instruction cache flush failed'}
   $modeDiscard=[uint32]0
   if(![TechnikaNormalCapture]::VirtualProtectEx($processHandle,[IntPtr]$modeAddress,[UIntPtr]([uint32]6),$modeProtect,[ref]$modeDiscard)){throw 'Cannot restore game-mode code page protection'}
   [pscustomobject]@{mode='native-free-play';address='0x412370';original=[BitConverter]::ToString($modeOriginal);replacement=[BitConverter]::ToString($modeReplacement);previousProtection=$modeProtect;scope='Built-in free-play mode for display, credit checks and debit; no fabricated coins'} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $PSScriptRoot "$Prefix-free-play-patch.json") -Encoding UTF8
  }
  [Runtime.InteropServices.Marshal]::WriteInt32($lastTrace.local,12,1)
  Start-Sleep -Seconds 10
 }
 if(!$CompactMode){
 $traceIndex=0
 foreach($trace in $vmTraces){
  $traceIndex++
  if(!$trace){continue}
  $tracePrefix=$Prefix
  if($traceIndex -gt 1){$tracePrefix="$Prefix-layer$traceIndex"}
  $traceBytes=New-Object byte[] $trace.size
  [Runtime.InteropServices.Marshal]::Copy($trace.local,$traceBytes,0,$traceBytes.Length)
  [IO.File]::WriteAllBytes((Join-Path $PSScriptRoot "$tracePrefix-vm-trace.bin"),$traceBytes)
  [pscustomobject]@{scope='Runtime replay after skipped dog checks; not original launch trace';count=[BitConverter]::ToUInt32($traceBytes,0);childHookInstalled=[BitConverter]::ToUInt32($traceBytes,4);intentionalHalt=[BitConverter]::ToUInt32($traceBytes,8);maxRecords=2048;recordSize=32;recordOffset=256;remoteAddress=$trace.remote.ToInt64();hookAddress=$trace.hookAddress;codeAddress=$trace.codeAddress;codeHex=$trace.codeHex} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $PSScriptRoot "$tracePrefix-vm-trace.json") -Encoding UTF8
 }
 }
 $threadExitCode=[uint32]0
 $threadExitKnown=[TechnikaNormalCapture]::GetExitCodeThread($dialogThread,[ref]$threadExitCode)
 [pscustomobject]@{threadId=$dialog.thread;querySuccess=$threadExitKnown;exitCode=$threadExitCode;stillActive=($threadExitKnown -and $threadExitCode -eq 259)} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $PSScriptRoot "$Prefix-after-thread.json") -Encoding UTF8
 if($targetProcess.HasExited){
  $processExit=[uint32]0
  $processExitKnown=[TechnikaNormalCapture]::GetExitCodeProcess($processHandle,[ref]$processExit)
  [pscustomobject]@{state='exited-after-runtime-experiment';experiment=$Experiment;exitCodeKnown=$processExitKnown;exitCode=$processExit} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $PSScriptRoot "$Prefix-after-force.json") -Encoding UTF8
 }else{
  $afterWindows=@([TechnikaNormalCapture]::Windows($TargetProcessId))
  [pscustomobject]@{state='alive-after-runtime-experiment';experiment=$Experiment;intentionalHaltRequested=[bool]$PauseLastLayer;windows=$afterWindows;modules=@($targetProcess.Modules | Select-Object ModuleName,FileName)} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $PSScriptRoot "$Prefix-after-force.json") -Encoding UTF8
  if(!$CompactMode){& (Join-Path $PSScriptRoot 'capture-client-memory.ps1') -TargetProcessId $TargetProcessId -OutputPrefix "$Prefix-after-force"}
  $downstreamDialog=$afterWindows | Where-Object {($_.title+' '+($_.children -join ' ')) -match 'Runtime Error|Error loading|Hardware Dog|Sentinel'} | Select-Object -First 1
  if(!$CompactMode -and $downstreamDialog){& (Join-Path $PSScriptRoot 'capture-owned-thread.ps1') -TargetProcessId $TargetProcessId -ThreadId ([int]$downstreamDialog.thread) -Prefix "$Prefix-downstream"}
  $gameWindow=$afterWindows | Where-Object {$_.title -eq 'ClientApp'} | Select-Object -First 1
  if(!$CompactMode -and $gameWindow){& (Join-Path $PSScriptRoot 'capture-owned-window.ps1') -TargetProcessId $TargetProcessId -WindowHandle ([long]$gameWindow.handle) -Prefix $Prefix}
 }
} finally {
 foreach($trace in $vmTraces){[void][TechnikaNormalCapture]::UnmapViewOfFile($trace.local);[void][TechnikaNormalCapture]::CloseHandle($trace.section)}
 [void][TechnikaNormalCapture]::CloseHandle($dialogThread);[void][TechnikaNormalCapture]::CloseHandle($processHandle)
}
