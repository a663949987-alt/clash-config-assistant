using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace ClashConfig {
 public sealed class GuardRequest { public string Scope; public string[] Paths; public ulong Tunnel; public bool Remove; }
 public static class Guard {
  [StructLayout(LayoutKind.Sequential)] struct Display { [MarshalAs(UnmanagedType.LPWStr)]public string Name;[MarshalAs(UnmanagedType.LPWStr)]public string Description; }
  [StructLayout(LayoutKind.Sequential)] struct Blob {public uint Size;public IntPtr Data;}
  [StructLayout(LayoutKind.Explicit,Size=16)] struct Value {[FieldOffset(0)]public uint Type;[FieldOffset(8)]public ulong Number;[FieldOffset(8)]public IntPtr Pointer;}
  [StructLayout(LayoutKind.Sequential)] struct Condition {public Guid Key;public uint Match;public Value Value;}
  [StructLayout(LayoutKind.Sequential)] struct ActionValue {public uint Type;public Guid Key;}
  [StructLayout(LayoutKind.Explicit,Size=16)] struct Context {[FieldOffset(0)]public ulong Number;[FieldOffset(0)]public Guid Key;}
  [StructLayout(LayoutKind.Sequential)] struct Filter {public Guid Key;public Display Display;public uint Flags;public IntPtr Provider;public Blob Data;public Guid Layer;public Guid SubLayer;public Value Weight;public uint Count;public IntPtr Conditions;public ActionValue Action;public Context Context;public IntPtr Reserved;public ulong Id;public Value EffectiveWeight;}
  [StructLayout(LayoutKind.Sequential)] struct SubLayer {public Guid Key;public Display Display;public uint Flags;public IntPtr Provider;public Blob Data;public ushort Weight;}
  static readonly Guid Layer4=new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82"),Layer6=new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
  static readonly Guid AppId=new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971"),LocalInterface=new Guid("4cd62a49-59c3-4969-b7f3-bda5d32890a4"),Flags=new Guid("632ce23b-5167-435c-86d7-e903684aa80c"),Remote=new Guid("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
  public static Guid Scope(){using(var s=SHA256.Create()){return new Guid(s.ComputeHash(Encoding.UTF8.GetBytes("ClashConfigGuard-v1-"+WindowsIdentity.GetCurrent().User.Value)).Take(16).ToArray());}}
  public static bool IsAdmin {get{return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);}}
  static void Check(uint code){if(code!=0)throw new InvalidOperationException("系统断网保护操作失败（0x"+code.ToString("X8")+"）。原保护规则已保留。");}
  public static void CheckLayout(){if(IntPtr.Size!=8||Marshal.SizeOf(typeof(Filter))!=200||Marshal.SizeOf(typeof(Condition))!=40||Marshal.SizeOf(typeof(SubLayer))!=72)throw new InvalidOperationException("此版本需要 64 位 Windows。");}
  static List<Filter> Enumerate(IntPtr engine,Guid scope,List<ulong> tunnels=null){
   var list=new List<Filter>();IntPtr e;Check(FwpmFilterCreateEnumHandle0(engine,IntPtr.Zero,out e));
   try{while(true){IntPtr entries;uint count;Check(FwpmFilterEnum0(engine,e,256,out entries,out count));try{for(uint i=0;i<count;i++){var f=(Filter)Marshal.PtrToStructure(Marshal.ReadIntPtr(entries,(int)i*IntPtr.Size),typeof(Filter));if(f.SubLayer==scope){list.Add(f);if(tunnels!=null)for(int j=0;j<f.Count;j++){var c=(Condition)Marshal.PtrToStructure(IntPtr.Add(f.Conditions,j*40),typeof(Condition));if(c.Key==LocalInterface&&c.Value.Type==4)tunnels.Add((ulong)Marshal.ReadInt64(c.Value.Pointer));}}}}finally{if(entries!=IntPtr.Zero)FwpmFreeMemory0(ref entries);}if(count==0)break;}}finally{FwpmFilterDestroyEnumHandle0(engine,e);}return list;
  }
  public static int Count(Guid scope){CheckLayout();IntPtr e;Check(FwpmEngineOpen0(null,10,IntPtr.Zero,IntPtr.Zero,out e));try{return Enumerate(e,scope).Count;}finally{FwpmEngineClose0(e);}}
  public static bool AllowsTunnel(Guid scope,ulong tunnel){IntPtr e;Check(FwpmEngineOpen0(null,10,IntPtr.Zero,IntPtr.Zero,out e));try{var values=new List<ulong>();Enumerate(e,scope,values);return tunnel!=0&&values.Count>0&&values.All(x=>x==tunnel);}finally{FwpmEngineClose0(e);}}
  static IntPtr Alloc(byte[] b,List<IntPtr> allocated){var p=Marshal.AllocHGlobal(b.Length);Marshal.Copy(b,0,p,b.Length);allocated.Add(p);return p;}
  static Condition PtrCondition(Guid key,uint type,IntPtr p){return new Condition{Key=key,Value=new Value{Type=type,Pointer=p}};}
  static void Add(IntPtr engine,Guid scope,Guid layer,IEnumerable<Condition> conditions,bool permit){
   var a=conditions.ToArray();IntPtr p=Marshal.AllocHGlobal(a.Length*Marshal.SizeOf(typeof(Condition)));
   try{for(int i=0;i<a.Length;i++)Marshal.StructureToPtr(a[i],IntPtr.Add(p,i*40),false);
    var f=new Filter{Key=Guid.NewGuid(),Display=new Display{Name="Clash App Guard",Description=permit?"Permit selected app through TUN/local network":"Block selected app bypass"},Flags=1,Layer=layer,SubLayer=scope,Weight=new Value{Type=1,Number=permit?15UL:0UL},Count=(uint)a.Length,Conditions=p,Action=new ActionValue{Type=permit?0x1002u:0x1001u}};
    ulong id;Check(FwpmFilterAdd0(engine,ref f,IntPtr.Zero,out id));
   }finally{Marshal.FreeHGlobal(p);}
  }
  public static void Apply(GuardRequest request){
   CheckLayout();if(!IsAdmin)throw new InvalidOperationException("启用系统断网保护需要管理员授权。");
   Guid scope=new Guid(request.Scope);if(scope!=Scope())throw new InvalidOperationException("请使用当前登录用户的管理员授权。");
   if(!request.Remove&&(request.Paths==null||request.Paths.Length==0||request.Tunnel==0))throw new InvalidOperationException("保护目标或虚拟网卡尚未准备好。");
   IntPtr engine;Check(FwpmEngineOpen0(null,10,IntPtr.Zero,IntPtr.Zero,out engine));bool transaction=false;
   try{
    var old=Enumerate(engine,scope);Check(FwpmTransactionBegin0(engine,0));transaction=true;
    foreach(var f in old){Guid key=f.Key;Check(FwpmFilterDeleteByKey0(engine,ref key));}
    if(!request.Remove){
     var sub=new SubLayer{Key=scope,Display=new Display{Name="Clash App Guard",Description="Per-user selected app proxy guard"},Flags=1,Weight=0x7fff};uint result=FwpmSubLayerAdd0(engine,ref sub,IntPtr.Zero);if(result!=0&&result!=0x80320009)Check(result);
     foreach(string input in request.Paths.Distinct(StringComparer.OrdinalIgnoreCase)){
      string path=Path.GetFullPath(input);string name=Path.GetFileName(path).ToLowerInvariant();
      if(!File.Exists(path)||!path.EndsWith(".exe",StringComparison.OrdinalIgnoreCase)||new[]{"svchost.exe","clash-verge.exe","verge-mihomo.exe","clashconfigassistant.exe"}.Contains(name))throw new InvalidOperationException("所选程序路径无效或属于系统共享进程。");
      IntPtr app;Check(FwpmGetAppIdFromFileName0(path,out app));var allocated=new List<IntPtr>();
      try{
       Condition c=PtrCondition(AppId,12,app);Condition tun=PtrCondition(LocalInterface,4,Alloc(BitConverter.GetBytes(request.Tunnel),allocated));
       Condition loop=new Condition{Key=Flags,Match=6,Value=new Value{Type=3,Number=1}};
       foreach(var layer in new[]{Layer4,Layer6}){Add(engine,scope,layer,new[]{c},false);Add(engine,scope,layer,new[]{c,tun},true);Add(engine,scope,layer,new[]{c,loop},true);}
       // Exempt only local communication needed by pairing and local services.
       foreach(var range in new[]{new uint[]{0x0A000000,0xFF000000},new uint[]{0xAC100000,0xFFF00000},new uint[]{0xC0A80000,0xFFFF0000},new uint[]{0xA9FE0000,0xFFFF0000}}){byte[] b=BitConverter.GetBytes(range[0]).Concat(BitConverter.GetBytes(range[1])).ToArray();Add(engine,scope,Layer4,new[]{c,PtrCondition(Remote,0x100,Alloc(b,allocated))},true);}
       foreach(var prefix in new[]{new byte[]{0xFC,0,7},new byte[]{0xFE,0x80,10}}){byte[] b=new byte[17];b[0]=prefix[0];b[1]=prefix[1];b[16]=prefix[2];Add(engine,scope,Layer6,new[]{c,PtrCondition(Remote,0x101,Alloc(b,allocated))},true);}
      }finally{foreach(var p in allocated)Marshal.FreeHGlobal(p);FwpmFreeMemory0(ref app);}
     }
    }
    Check(FwpmTransactionCommit0(engine));transaction=false;
   }finally{if(transaction)FwpmTransactionAbort0(engine);FwpmEngineClose0(engine);}
  }
  [DllImport("fwpuclnt.dll",CharSet=CharSet.Unicode)]static extern uint FwpmEngineOpen0(string server,uint auth,IntPtr identity,IntPtr session,out IntPtr engine);
  [DllImport("fwpuclnt.dll")]static extern uint FwpmEngineClose0(IntPtr engine);
  [DllImport("fwpuclnt.dll")]static extern uint FwpmTransactionBegin0(IntPtr engine,uint flags);
  [DllImport("fwpuclnt.dll")]static extern uint FwpmTransactionCommit0(IntPtr engine);
  [DllImport("fwpuclnt.dll")]static extern uint FwpmTransactionAbort0(IntPtr engine);
  [DllImport("fwpuclnt.dll",CharSet=CharSet.Unicode)]static extern uint FwpmGetAppIdFromFileName0(string file,out IntPtr blob);
  [DllImport("fwpuclnt.dll")]static extern void FwpmFreeMemory0(ref IntPtr memory);
  [DllImport("fwpuclnt.dll",CharSet=CharSet.Unicode)]static extern uint FwpmFilterAdd0(IntPtr engine,ref Filter filter,IntPtr security,out ulong id);
  [DllImport("fwpuclnt.dll",CharSet=CharSet.Unicode)]static extern uint FwpmSubLayerAdd0(IntPtr engine,ref SubLayer layer,IntPtr security);
  [DllImport("fwpuclnt.dll")]static extern uint FwpmFilterDeleteByKey0(IntPtr engine,ref Guid key);
  [DllImport("fwpuclnt.dll")]static extern uint FwpmFilterCreateEnumHandle0(IntPtr engine,IntPtr template,out IntPtr handle);
  [DllImport("fwpuclnt.dll")]static extern uint FwpmFilterEnum0(IntPtr engine,IntPtr handle,uint max,out IntPtr entries,out uint count);
  [DllImport("fwpuclnt.dll")]static extern uint FwpmFilterDestroyEnumHandle0(IntPtr engine,IntPtr handle);
 }
}
