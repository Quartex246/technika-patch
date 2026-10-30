using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class TechnikaNormalCapture {
 public delegate bool EnumProc(IntPtr window, IntPtr parameter);
 [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc callback, IntPtr parameter);
 [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr window, EnumProc callback, IntPtr parameter);
 [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr window, out uint process);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr window,StringBuilder text,int size);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr window,StringBuilder text,int size);
 [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr window);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern IntPtr OpenProcess(uint access,bool inherit,int id);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern IntPtr OpenThread(uint access,bool inherit,int id);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern uint SuspendThread(IntPtr thread);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern uint ResumeThread(IntPtr thread);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool GetExitCodeThread(IntPtr thread,out uint exitCode);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool GetExitCodeProcess(IntPtr process,out uint exitCode);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool Wow64GetThreadContext(IntPtr thread,IntPtr context);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool ReadProcessMemory(IntPtr process,IntPtr address,byte[] data,UIntPtr size,out UIntPtr read);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern IntPtr VirtualAllocEx(IntPtr process,IntPtr address,UIntPtr size,uint type,uint protect);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool VirtualProtectEx(IntPtr process,IntPtr address,UIntPtr size,uint protect,out uint previous);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool WriteProcessMemory(IntPtr process,IntPtr address,byte[] bytes,UIntPtr size,out UIntPtr written);
 [DllImport("kernel32.dll")] public static extern bool FlushInstructionCache(IntPtr process,IntPtr address,UIntPtr size);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern IntPtr CreateFileMapping(IntPtr file,IntPtr attributes,uint protect,uint high,uint low,string name);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern IntPtr MapViewOfFile(IntPtr mapping,uint access,uint high,uint low,UIntPtr size);
 [DllImport("kernel32.dll")] public static extern bool UnmapViewOfFile(IntPtr view);
 [DllImport("ntdll.dll")] public static extern int NtMapViewOfSection(IntPtr section,IntPtr process,ref IntPtr address,UIntPtr zeroBits,UIntPtr commit,IntPtr offset,ref UIntPtr size,uint inherit,uint allocation,uint protect);
 [DllImport("user32.dll",SetLastError=true)] public static extern bool PostMessage(IntPtr window,uint message,UIntPtr wparam,IntPtr lparam);
 [DllImport("user32.dll",SetLastError=true)] public static extern IntPtr GetDlgItem(IntPtr window,int id);
 [DllImport("user32.dll",SetLastError=true)] public static extern IntPtr SendMessageTimeout(IntPtr window,uint message,UIntPtr wparam,IntPtr lparam,uint flags,uint timeout,out UIntPtr result);
 [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr handle);
 public class Child { public long handle;public int id;public string text;public string className; }
 public class Window { public long handle;public uint thread;public string title;public List<string> children=new List<string>();public List<Child> controls=new List<Child>(); }
 public static List<Window> Windows(int pid) {
  var result=new List<Window>();
  EnumWindows((w,p)=>{uint owner;uint tid=GetWindowThreadProcessId(w,out owner);if(owner!=(uint)pid)return true;
   var text=new StringBuilder(1024);GetWindowText(w,text,text.Capacity);var item=new Window{handle=w.ToInt64(),thread=tid,title=text.ToString()};
   EnumChildWindows(w,(c,q)=>{var child=new StringBuilder(2048);GetWindowText(c,child,child.Capacity);if(child.Length>0)item.children.Add(child.ToString());var cl=new StringBuilder(256);GetClassName(c,cl,cl.Capacity);item.controls.Add(new Child{handle=c.ToInt64(),id=GetDlgCtrlID(c),text=child.ToString(),className=cl.ToString()});return true;},IntPtr.Zero);
   result.Add(item);return true;},IntPtr.Zero);return result;
 }
}
