param([IntPtr]$ProcessHandle,[long]$CodeAddress,[long]$HookAddress=0xF2BEE01,[uint32]$IpGlobal=0xF2B112C,[uint32]$SpGlobal=0xF2B1128,[uint32]$CommandGlobal=0xF2B5E18,[bool]$HookNow=$true,$FollowupHook=$null,[uint32]$TriggerIp=0xF2B0010,[uint32]$TriggerIp2=0,[uint32]$StopIp=0,[uint32]$StopIp2=0)
$ErrorActionPreference='Stop'
# Anonymous shared memory retains the controlled test's VM log after its exit.
$size=[uint32]0x20000
$section=[TechnikaNormalCapture]::CreateFileMapping([IntPtr](-1),[IntPtr]::Zero,4,0,$size,$null)
if($section -eq [IntPtr]::Zero){throw 'Cannot create VM trace mapping'}
$local=[TechnikaNormalCapture]::MapViewOfFile($section,0xF001F,0,0,[UIntPtr]$size)
if($local -eq [IntPtr]::Zero){[void][TechnikaNormalCapture]::CloseHandle($section);throw 'Cannot map local VM trace'}
try {
 $remote=[IntPtr]::Zero
 $viewSize=[UIntPtr]$size
 $mapStatus=[TechnikaNormalCapture]::NtMapViewOfSection($section,$ProcessHandle,[ref]$remote,[UIntPtr]::Zero,[UIntPtr]::Zero,[IntPtr]::Zero,[ref]$viewSize,2,0,4)
 if($mapStatus -ne 0 -or $remote.ToInt64() -gt [uint32]::MaxValue){throw "Cannot map 32-bit VM trace: $mapStatus"}
 $remoteBase=[uint32]$remote.ToInt64()
 $code=New-Object 'System.Collections.Generic.List[byte]'
 function Add-Bytes([byte[]]$bytes){$code.AddRange($bytes)}
 function Add-Dword([uint32]$value){$code.AddRange([BitConverter]::GetBytes($value))}
 # Preserve all state; each 32-byte row contains IP, instruction, operand data,
 # VM SP, top value, two key-related globals, and the previous opcode/operand.
 Add-Bytes @(0x9C,0x60,0xFC,0xA1);Add-Dword $remoteBase
 Add-Bytes @(0x3D,0,8,0,0,0x0F,0x83)
 $skipOffset=$code.Count;Add-Dword 0
 Add-Bytes @(0xC1,0xE0,5,0x05);Add-Dword ($remoteBase+0x100)
 Add-Bytes @(0x8B,0xF8,0xA1);Add-Dword $IpGlobal
 Add-Bytes @(0xAB,0x8B,0xD0,0x8B,0x02,0xAB,0x8B,0x42,4,0xAB,0xA1);Add-Dword $SpGlobal
 Add-Bytes @(0xAB,0x8B,0,0xAB,0xA1);Add-Dword 0xF2AE8D0
 Add-Bytes @(0xAB,0xA1);Add-Dword 0xF2AE8D4
 Add-Bytes @(0xAB,0xA1);Add-Dword $CommandGlobal
 Add-Bytes @(0xAB,0xFF,5);Add-Dword $remoteBase
 $doneOffset=$code.Count
 if($FollowupHook){
  # The child VM is encrypted until the parent reaches its normal terminator.
  # Install its hook only then, after the parent has verified the decrypted data.
  Add-Bytes @(0xA1);Add-Dword $IpGlobal
  Add-Bytes @(0x3D);Add-Dword $TriggerIp
  if($TriggerIp2){Add-Bytes @(0x74,7,0x3D);Add-Dword $TriggerIp2}
  Add-Bytes @(0x75);$followSkip1=$code.Count;Add-Bytes @(0)
  Add-Bytes @(0x81,0x3D);Add-Dword ([uint32]$FollowupHook.hookAddress);Add-Dword ([BitConverter]::ToUInt32($FollowupHook.expectedBytes,0))
  Add-Bytes @(0x75);$followSkip2=$code.Count;Add-Bytes @(0)
  Add-Bytes @(0x80,0x3D);Add-Dword ([uint32]($FollowupHook.hookAddress+4));Add-Bytes @($FollowupHook.expectedBytes[4])
  Add-Bytes @(0x75);$followSkip3=$code.Count;Add-Bytes @(0)
  Add-Bytes @(0xC7,0x05);Add-Dword ([uint32]$FollowupHook.hookAddress);Add-Dword ([BitConverter]::ToUInt32($FollowupHook.jumpBytes,0))
  Add-Bytes @(0xC6,0x05);Add-Dword ([uint32]($FollowupHook.hookAddress+4));Add-Bytes @($FollowupHook.jumpBytes[4])
  Add-Bytes @(0xC7,0x05);Add-Dword ($remoteBase+4);Add-Dword 1
  foreach($fix in @($followSkip1,$followSkip2,$followSkip3)){$code[$fix]=[byte]($code.Count-$fix-1)}
 }
 if($StopIp -ne 0){
  Add-Bytes @(0xA1);Add-Dword $IpGlobal
  Add-Bytes @(0x3D);Add-Dword $StopIp
  if($StopIp2){Add-Bytes @(0x74,7,0x3D);Add-Dword $StopIp2}
  Add-Bytes @(0x75);$pauseSkip=$code.Count;Add-Bytes @(0)
  Add-Bytes @(0xC7,0x05);Add-Dword ($remoteBase+8);Add-Dword 1
  # The owner may release the halt through shared flag +12 after a verified
  # body patch; otherwise it captures memory then terminates its test process.
  $pauseLoop=$code.Count
  Add-Bytes @(0x83,0x3D);Add-Dword ($remoteBase+12);Add-Bytes @(0,0x75,4,0xF3,0x90,0xEB)
  Add-Bytes @([byte](256+$pauseLoop-$code.Count-1))
  $code[$pauseSkip]=[byte]($code.Count-$pauseSkip-1)
 }
 Add-Bytes @(0x61,0x9D,0xA1);Add-Dword $IpGlobal
 Add-Bytes @(0xE9)
 $code.AddRange([BitConverter]::GetBytes([int32]($HookAddress+5-$CodeAddress-$code.Count-4)))
 $bytes=$code.ToArray()
 [BitConverter]::GetBytes([int32]($doneOffset-$skipOffset-4)).CopyTo($bytes,$skipOffset)
 Write-TargetBytes $CodeAddress $bytes
 $expected=New-Object byte[] 5;$expected[0]=0xA1;[BitConverter]::GetBytes($IpGlobal).CopyTo($expected,1)
 if($HookNow){
  $actual=New-Object byte[] 5;$read=[UIntPtr]::Zero
  if(![TechnikaNormalCapture]::ReadProcessMemory($ProcessHandle,[IntPtr]$HookAddress,$actual,[UIntPtr]([uint32]5),[ref]$read) -or [BitConverter]::ToString($actual) -ne [BitConverter]::ToString($expected)){throw 'VM dispatch bytes differ; refusing instrumentation'}
 }
 $oldProtect=[uint32]0
 if(![TechnikaNormalCapture]::VirtualProtectEx($ProcessHandle,[IntPtr]$HookAddress,[UIntPtr]([uint32]5),0x40,[ref]$oldProtect)){throw 'Cannot instrument owned VM dispatch'}
 $jump=New-Object byte[] 5;$jump[0]=0xE9
 [BitConverter]::GetBytes([int32]($CodeAddress-$HookAddress-5)).CopyTo($jump,1)
 if($HookNow){Write-TargetBytes $HookAddress $jump}
 return [pscustomobject]@{section=$section;local=$local;remote=$remote;size=$size;codeAddress=$CodeAddress;codeHex=[BitConverter]::ToString($bytes);hookAddress=$HookAddress;originalHex=[BitConverter]::ToString($expected);expectedBytes=$expected;jumpBytes=$jump}
}catch{
 [void][TechnikaNormalCapture]::UnmapViewOfFile($local)
 [void][TechnikaNormalCapture]::CloseHandle($section)
 throw
}
