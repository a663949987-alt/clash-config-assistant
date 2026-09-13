using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace ClashConfig {
 public static class LocalMemory {
  public static string FilePath {get{return Path.Combine(Core.Data,"preferences.bin");}}
  public static void Save(Input input){
   Directory.CreateDirectory(Core.Data);
   byte[] bytes=ProtectedData.Protect(Encoding.UTF8.GetBytes(Core.Json.Serialize(input)),null,DataProtectionScope.CurrentUser);
   string temp=FilePath+"."+Guid.NewGuid().ToString("N")+".tmp";
   try{File.WriteAllBytes(temp,bytes);if(File.Exists(FilePath))File.Replace(temp,FilePath,null);else File.Move(temp,FilePath);}finally{if(File.Exists(temp))File.Delete(temp);}
  }
  public static Input Load(){if(!File.Exists(FilePath))return null;return Core.Json.Deserialize<Input>(Encoding.UTF8.GetString(ProtectedData.Unprotect(File.ReadAllBytes(FilePath),null,DataProtectionScope.CurrentUser)));}
  public static void Clear(){if(File.Exists(FilePath))File.Delete(FilePath);}
  public static void Test(string report){
   string old=Core.Data;Core.Data=Path.Combine(Path.GetTempPath(),"ClashMemoryTest-"+Guid.NewGuid().ToString("N"));
   try{if(Load()!=null)throw new Exception("Initial state");var input=new Input{Kind="SOCKS5",Address="localhost:1080",Username="test-user",Password="test-only-secret",Paths=new[]{@"C:\test\app.exe"},AutoStart=true};Save(input);var restored=Load();if(restored.Password!=input.Password||restored.Paths[0]!=input.Paths[0]||!restored.AutoStart)throw new Exception("Round trip");if(Encoding.UTF8.GetString(File.ReadAllBytes(FilePath)).Contains(input.Password))throw new Exception("Plaintext");input.Password="updated";Save(input);if(Load().Password!="updated")throw new Exception("Replace");File.WriteAllBytes(FilePath,new byte[]{1,2,3});bool rejected=false;try{Load();}catch(CryptographicException){rejected=true;}if(!rejected)throw new Exception("Corrupt payload");Clear();if(Load()!=null)throw new Exception("Clear");File.WriteAllText(report,"PASS: encrypted persistence, credentials and app-path round trip, atomic replacement, corrupt-file rejection and forgetting.");}finally{if(Directory.Exists(Core.Data))Directory.Delete(Core.Data,true);Core.Data=old;}
  }
 }
}
