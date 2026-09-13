using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using Microsoft.Win32;
using YamlDotNet.RepresentationModel;

namespace ClashConfig {
 public sealed class Choice {public string Name;public string[] Paths;public override string ToString(){return Name;}}
 public sealed class Input {public string Kind,Address,Username,Password;public bool AutoStart;public int RuleMode;public string NodeName;public string[] Paths;}
 public sealed class SavedState {public string Backup;public string[] Paths;public string Scope;public string ConfigRoot;public bool HasGuard;public int RuleMode;public string TestIP,NodeName;}
 public sealed class BackupInfo {public string[] Present;public bool AutoRunExists,ProxyExists,ApprovedExists;public string AutoRun,OldState;public int Proxy;public byte[] Approved;}
 public sealed class Prepared {public string Yaml;public string[] Paths;public string TestIP;public int RuleMode;public string NodeName;}
 public sealed class Operation {public string Action;public Prepared Prepared;public bool AutoStart;}
 public static class Core {
  public static string Data=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"ClashConfigAssistant");
  public static string ConfigRoot=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),"io.github.clash-verge-rev.clash-verge-rev");
  public const string ProfileId="Lccaapp",ScriptId="sccaapp",Group="Selected-Apps-Proxy";
  public static string[] Managed={"profiles.yaml","verge.yaml","config.yaml","profiles\\Lccaapp.yaml","profiles\\sccaapp.js"};
  public static JavaScriptSerializer Json=new JavaScriptSerializer{MaxJsonLength=8000000};
  static UTF8Encoding UTF8=new UTF8Encoding(false);
  public static string Exe {get{return System.Reflection.Assembly.GetExecutingAssembly().Location;}}
  public static string ClashExe {get{
   foreach(var root in new[]{Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Programs")}){var path=Path.Combine(root,"Clash Verge","clash-verge.exe");if(File.Exists(path))return path;}
   using(var k=Registry.CurrentUser.OpenSubKey("Software\\ClashConfigAssistant")){string path=k==null?null:k.GetValue("ClashPath") as string;if(path!=null&&File.Exists(path)&&Path.GetFileName(path).Equals("clash-verge.exe",StringComparison.OrdinalIgnoreCase))return path;}return null;
  }}
  public static string CoreExe {get{return ClashExe==null?null:Path.Combine(Path.GetDirectoryName(ClashExe),"verge-mihomo.exe");}}
  public static void RequireClash(){if(ClashExe==null||!File.Exists(CoreExe))throw new InvalidOperationException("未找到 Clash Verge Rev。请先安装官方客户端，或选择已安装的 clash-verge.exe。");foreach(string f in new[]{"profiles.yaml","verge.yaml","config.yaml"})if(!File.Exists(Path.Combine(ConfigRoot,f)))throw new InvalidOperationException("请先打开一次 Clash Verge Rev，让它建立配置目录。");}
  public static YamlMappingNode Parse(string text){
   if(text==null||text.Length>2*1024*1024)throw new InvalidOperationException("配置为空或超过 2 MB。");
   try{var stream=new YamlStream();stream.Load(new StringReader(text));if(stream.Documents.Count!=1||!(stream.Documents[0].RootNode is YamlMappingNode))throw new Exception();return (YamlMappingNode)stream.Documents[0].RootNode;}catch{throw new InvalidOperationException("内容不是有效的 Clash YAML 配置。请检查链接类型或改用代理地址。");}
  }
  public static YamlNode Get(YamlMappingNode m,string k){YamlNode v;return m.Children.TryGetValue(new YamlScalarNode(k),out v)?v:null;}
  public static string Str(YamlNode n){var s=n as YamlScalarNode;return s==null?null:s.Value;}
  public static void Set(YamlMappingNode m,string k,YamlNode v){m.Children[new YamlScalarNode(k)]=v;}
  public static YamlScalarNode S(string s){return new YamlScalarNode(s);}
  public static string Dump(YamlMappingNode map){var writer=new StringWriter();new YamlStream(new YamlDocument(map)).Save(writer,false);return writer.ToString();}
  public static void Write(string path,string text){Directory.CreateDirectory(Path.GetDirectoryName(path));string tmp=path+".cca-tmp";File.WriteAllText(tmp,text,UTF8);if(File.Exists(path))File.Replace(tmp,path,null);else File.Move(tmp,path);}
  public static List<string> Rules(string[] paths){
   if(paths==null||paths.Length==0)throw new InvalidOperationException("请至少选择一个应用。本软件不会自动预选。");
   var result=new List<string>{"IP-CIDR,127.0.0.0/8,DIRECT,no-resolve","IP-CIDR,10.0.0.0/8,DIRECT,no-resolve","IP-CIDR,172.16.0.0/12,DIRECT,no-resolve","IP-CIDR,192.168.0.0/16,DIRECT,no-resolve","IP-CIDR,169.254.0.0/16,DIRECT,no-resolve","IP-CIDR6,::1/128,DIRECT,no-resolve","IP-CIDR6,fe80::/10,DIRECT,no-resolve","IP-CIDR6,fc00::/7,DIRECT,no-resolve"};
   foreach(string p in paths.Distinct(StringComparer.OrdinalIgnoreCase)){
    if(p.IndexOfAny(new[]{',','\r','\n','"'})>=0||!Path.IsPathRooted(p)||!p.EndsWith(".exe",StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("程序路径格式不支持，请重新选择 EXE。");
    result.Add("PROCESS-PATH,"+p+","+Group);result.Add("PROCESS-PATH,"+p+",REJECT");
   }foreach(string name in paths.Select(Path.GetFileName).Distinct(StringComparer.OrdinalIgnoreCase))result.Add("PROCESS-NAME,"+name+",REJECT");result.Add("PROCESS-NAME-REGEX,^.+$,DIRECT");result.Add("MATCH,REJECT");return result;
  }
  public static string Build(string raw,string[] paths,int ruleMode=0){
   var source=Parse(raw);var proxies=Get(source,"proxies") as YamlSequenceNode;
   if(proxies==null||proxies.Children.Count==0)throw new InvalidOperationException("此链接没有直接节点。请使用包含 proxies 的 Clash 订阅，暂不支持 provider-only 或 Base64 分享链接。");
   var names=new HashSet<string>(StringComparer.Ordinal);var list=new YamlSequenceNode();
   foreach(var p in proxies.Children){var m=p as YamlMappingNode;if(m==null)throw new InvalidOperationException("节点格式不正确。");string name=Str(Get(m,"name")),type=Str(Get(m,"type"));if(String.IsNullOrEmpty(name)||!names.Add(name)||new[]{"DIRECT","REJECT",Group}.Contains(name)||String.IsNullOrEmpty(type)||new[]{"direct","reject","dns"}.Contains(type.ToLowerInvariant()))throw new InvalidOperationException("订阅含空节点、重复名称或直连节点，严格模式不接受该配置。");list.Add(S(name));}
   var output=new YamlMappingNode();Set(output,"proxies",proxies);
   var group=new YamlMappingNode();Set(group,"name",S(Group));Set(group,"type",S("select"));Set(group,"proxies",list);Set(group,"udp",S("true"));Set(output,"proxy-groups",new YamlSequenceNode(group));
   Set(output,"rules",new YamlSequenceNode((ruleMode==2?Mode2.Rules(paths):Rules(paths)).Select(S)));Set(output,"find-process-mode",S("always"));Set(output,"mode",S("rule"));Set(output,"allow-lan",S("false"));Set(output,"ipv6",S("true"));if(ruleMode==2)Set(output,"sniffer",Get(Parse("sniffer: "+Mode2.SnifferJson),"sniffer"));return Dump(output);
  }
  public static string Direct(Input i){
   string scheme=i.Kind=="SOCKS5"?"socks5":"http";string address=i.Address.Trim();Uri uri;if(!Uri.TryCreate(address.Contains("://")?address:scheme+"://"+address,UriKind.Absolute,out uri)||uri.Host.Length==0||uri.Port<1||uri.Port>65535||uri.Query.Length>0||uri.Fragment.Length>0||(uri.AbsolutePath!=""&&uri.AbsolutePath!="/")||uri.Scheme!=scheme)throw new InvalidOperationException("请填写正确的主机:端口，或匹配类型的完整代理 URL。IPv6 地址需放在方括号内。");
   string user=i.Username??"",password=i.Password??"";
   if(!String.IsNullOrEmpty(uri.UserInfo)){if(user.Length>0||password.Length>0)throw new InvalidOperationException("URL 已有账号信息，请不要再重复填写账号密码。");var parts=uri.UserInfo.Split(new[]{':'},2);user=Uri.UnescapeDataString(parts[0]);password=parts.Length>1?Uri.UnescapeDataString(parts[1]):"";}
   var node=new YamlMappingNode();Set(node,"name",S("Proxy-1"));Set(node,"type",S(scheme));Set(node,"server",S(uri.Host.Trim('[',']')));Set(node,"port",S(uri.Port.ToString()));if(user.Length>0||password.Length>0){Set(node,"username",new YamlScalarNode(user){Style=YamlDotNet.Core.ScalarStyle.DoubleQuoted});Set(node,"password",new YamlScalarNode(password){Style=YamlDotNet.Core.ScalarStyle.DoubleQuoted});}if(scheme=="socks5")Set(node,"udp",S("true"));var root=new YamlMappingNode();Set(root,"proxies",new YamlSequenceNode(node));return Dump(root);
  }
  static string Download(string url){
   Uri uri;if(!Uri.TryCreate(url.Trim(),UriKind.Absolute,out uri)||uri.Scheme!="https"||!String.IsNullOrEmpty(uri.UserInfo))throw new InvalidOperationException("订阅请填写 HTTPS 链接，不要填写带网页登录的管理后台地址。");
   try{var request=(HttpWebRequest)WebRequest.Create(uri);request.Proxy=null;request.Timeout=25000;request.ReadWriteTimeout=25000;request.AllowAutoRedirect=false;request.UserAgent="clash-verge/v2.5.2";
    using(var response=(HttpWebResponse)request.GetResponse()){if(response.StatusCode!=HttpStatusCode.OK)throw new Exception();using(var stream=response.GetResponseStream()){var ms=new MemoryStream();byte[] b=new byte[8192];int n;while((n=stream.Read(b,0,b.Length))>0){ms.Write(b,0,n);if(ms.Length>2*1024*1024)throw new Exception();}return Encoding.UTF8.GetString(ms.ToArray());}}
   }catch{throw new InvalidOperationException("订阅获取失败。请检查有效期、网络和 HTTPS 链接；当前 Clash 配置未修改。");}
  }
  static int FreePort(){var t=new TcpListener(IPAddress.Loopback,0);t.Start();int p=((IPEndPoint)t.LocalEndpoint).Port;t.Stop();return p;}
  static string Quote(string s){return "\""+s.Replace("\"", "")+"\"";}
  static Process LaunchCore(string file,string root,bool validate){var info=new ProcessStartInfo(CoreExe,(validate?"-t ":"")+"-d "+Quote(root)+" -f "+Quote(file)){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};var p=Process.Start(info);p.OutputDataReceived+=(s,e)=>{};p.ErrorDataReceived+=(s,e)=>{};p.BeginOutputReadLine();p.BeginErrorReadLine();return p;}
  public static Prepared Prepare(Input input,Action<string> log){
   RequireClash();if(input.RuleMode==2){Rules(input.Paths);input.Paths=Mode2.Expand(input.Paths);}Rules(input.Paths);foreach(string p in input.Paths)if(!File.Exists(p))throw new InvalidOperationException("某个所选 EXE 已不存在，请重新选择。");
   log("正在检查代理内容……");string raw=input.Kind=="Clash 订阅"?Download(input.Address):Direct(input);if(input.RuleMode==2&&input.Kind=="Clash 订阅")raw=Mode2.SelectNode(raw,input.NodeName);string yaml=Build(raw,input.Paths,input.RuleMode);
   string stage=Path.Combine(Data,"staging",Guid.NewGuid().ToString("N"));Directory.CreateDirectory(stage);Process core=null;
   try{
    var test=Parse(yaml);int port=FreePort();Set(test,"mixed-port",S(port.ToString()));Set(test,"tun",new YamlMappingNode(S("enable"),S("false")));Set(test,"external-controller",S(""));Set(test,"log-level",S("silent"));string file=Path.Combine(stage,"test.yaml");Write(file,Dump(test));
    using(var check=LaunchCore(file,stage,true)){if(!check.WaitForExit(20000)){check.Kill();throw new InvalidOperationException("内核校验超时，未修改现有配置。");}if(check.ExitCode!=0)throw new InvalidOperationException("节点未通过 Mihomo 校验。请检查协议、端口、账号密码或订阅兼容性。");}
    Set(test,"rules",new YamlSequenceNode(S("MATCH,"+Group)));Write(file,Dump(test));log("配置格式有效，正在测试代理出口……");core=LaunchCore(file,stage,false);string found=null;
    for(int retry=0;retry<30;retry++){if(core.HasExited)throw new InvalidOperationException("测试内核未能启动。");try{using(var socket=new TcpClient()){socket.Connect(IPAddress.Loopback,port);}break;}catch{Thread.Sleep(100);}}
    var failures=new List<string>();foreach(string endpoint in new[]{"https://api.ipify.org","http://myip.ipip.net"}){
     try{var r=(HttpWebRequest)WebRequest.Create(endpoint);r.Proxy=new WebProxy("127.0.0.1",port);r.Timeout=12000;r.ReadWriteTimeout=12000;using(var response=r.GetResponse())using(var reader=new StreamReader(response.GetResponseStream())){string body=reader.ReadToEnd();var match=Regex.Match(body,@"\b(?:\d{1,3}\.){3}\d{1,3}\b");IPAddress ip;if(match.Success&&IPAddress.TryParse(match.Value,out ip)){found=ip.ToString();break;}if(IPAddress.TryParse(body.Trim(),out ip)){found=ip.ToString();break;}failures.Add("InvalidResponse");}}catch(WebException e){failures.Add(e.Status.ToString()+(e.Response is HttpWebResponse?"/"+(int)((HttpWebResponse)e.Response).StatusCode:""));}catch(Exception e){failures.Add(e.GetType().Name);}
    }
    if(found==null)throw new InvalidOperationException("节点未通过出口连通测试（"+String.Join(", ",failures)+"）。不会应用或回退直连。");log("代理出口测试成功："+found);return new Prepared{Yaml=yaml,Paths=input.Paths,TestIP=found,RuleMode=input.RuleMode,NodeName=input.RuleMode==2?Str(Get((YamlMappingNode)((YamlSequenceNode)Get(Parse(yaml),"proxies")).Children[0],"name")):null};
   }finally{if(core!=null){try{if(!core.HasExited){core.Kill();core.WaitForExit(5000);}}finally{core.Dispose();}}try{Directory.Delete(stage,true);}catch{}}
  }
  public static object Api(string route){
   var conf=Parse(File.ReadAllText(Path.Combine(ConfigRoot,"config.yaml")));string secret=Str(Get(conf,"secret"))??"";
   using(var pipe=new NamedPipeClientStream(".","verge-mihomo",PipeDirection.InOut,PipeOptions.Asynchronous)){
    pipe.Connect(3000);byte[] request=Encoding.ASCII.GetBytes("GET "+route+" HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer "+secret+"\r\nConnection: close\r\n\r\n");pipe.Write(request,0,request.Length);
    var read=Task.Run(()=>{using(var m=new MemoryStream()){pipe.CopyTo(m);return m.ToArray();}});if(!read.Wait(8000))throw new InvalidOperationException("Clash 控制接口响应超时。");byte[] bytes=read.Result;string text=Encoding.UTF8.GetString(bytes);int split=text.IndexOf("\r\n\r\n",StringComparison.Ordinal);if(split<0||!text.StartsWith("HTTP/1.1 200"))throw new InvalidOperationException("Clash 控制接口尚未就绪。");string headers=text.Substring(0,split),body=text.Substring(split+4);if(headers.IndexOf("chunked",StringComparison.OrdinalIgnoreCase)>=0){var result=new StringBuilder();int offset=0;while(true){int end=body.IndexOf("\r\n",offset,StringComparison.Ordinal);int length=Convert.ToInt32(body.Substring(offset,end-offset).Split(';')[0],16);if(length==0)break;offset=end+2;byte[] remaining=Encoding.UTF8.GetBytes(body.Substring(offset));string chunk=Encoding.UTF8.GetString(remaining,0,length);result.Append(chunk);offset+=chunk.Length+2;}body=result.ToString();}return Json.DeserializeObject(body);
   }
  }
  public static ulong Tunnel(){foreach(var n in NetworkInterface.GetAllNetworkInterfaces()){if(n.OperationalStatus!=OperationalStatus.Up)continue;if(n.Description.IndexOf("Meta",StringComparison.OrdinalIgnoreCase)<0&&n.Description.IndexOf("Mihomo",StringComparison.OrdinalIgnoreCase)<0)continue;var ip=n.GetIPProperties().GetIPv4Properties();if(ip==null)continue;ulong luid;if(ConvertInterfaceIndexToLuid((uint)ip.Index,out luid)==0)return luid;}return 0;}
  static bool RunningSelected(string[] paths){foreach(var p in Process.GetProcesses()){try{if(paths.Contains(p.MainModule.FileName,StringComparer.OrdinalIgnoreCase))return true;}catch{}finally{p.Dispose();}}return false;}
  static bool CloseClash(){bool running=false;foreach(var p in Process.GetProcessesByName("clash-verge")){try{if(!String.Equals(p.MainModule.FileName,ClashExe,StringComparison.OrdinalIgnoreCase))continue;running=true;p.Kill();if(!p.WaitForExit(8000))throw new InvalidOperationException("Clash 正在退出，请稍后重试。");}finally{p.Dispose();}}return running;}
  public static void OpenClash(){RequireClash();Process.Start(new ProcessStartInfo(ClashExe){UseShellExecute=true});}
  static BackupInfo Snapshot(string folder){
   Directory.CreateDirectory(folder);var present=new List<string>();foreach(string rel in Managed){string src=Path.Combine(ConfigRoot,rel);if(File.Exists(src)){string dest=Path.Combine(folder,rel);Directory.CreateDirectory(Path.GetDirectoryName(dest));File.Copy(src,dest);present.Add(rel);}}
   var b=new BackupInfo{Present=present.ToArray(),OldState=File.Exists(Path.Combine(Data,"state.json"))?File.ReadAllText(Path.Combine(Data,"state.json")):null};
   using(var run=Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Run")){object value=run==null?null:run.GetValue("Clash Verge");b.AutoRunExists=value!=null;b.AutoRun=value as string;}
   using(var k=Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run")){b.Approved=k==null?null:k.GetValue("Clash Verge") as byte[];b.ApprovedExists=b.Approved!=null;}
   using(var k=Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings")){object value=k==null?null:k.GetValue("ProxyEnable");b.ProxyExists=value!=null;b.Proxy=value==null?0:Convert.ToInt32(value);}
   Write(Path.Combine(folder,"snapshot.json"),Json.Serialize(b));return b;
  }
  static void RestoreFiles(string folder,BackupInfo b,bool system=true){foreach(string rel in Managed){string target=Path.Combine(ConfigRoot,rel);if(b.Present.Contains(rel)){Write(target,File.ReadAllText(Path.Combine(folder,rel)));}else if(File.Exists(target))File.Delete(target);}if(!system)return;using(var run=Registry.CurrentUser.CreateSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Run")){if(b.AutoRunExists)run.SetValue("Clash Verge",b.AutoRun);else run.DeleteValue("Clash Verge",false);}using(var k=Registry.CurrentUser.CreateSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run")){if(b.ApprovedExists)k.SetValue("Clash Verge",b.Approved,RegistryValueKind.Binary);else k.DeleteValue("Clash Verge",false);}using(var k=Registry.CurrentUser.CreateSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings")){if(b.ProxyExists)k.SetValue("ProxyEnable",b.Proxy,RegistryValueKind.DWord);else k.DeleteValue("ProxyEnable",false);}InternetSetOption(IntPtr.Zero,39,IntPtr.Zero,0);InternetSetOption(IntPtr.Zero,37,IntPtr.Zero,0);}
  public static void TestStorage(string folder){string before=ConfigRoot,oldData=Data;try{ConfigRoot=Path.Combine(folder,"fixture");Data=Path.Combine(folder,"fixture-data");Write(Path.Combine(ConfigRoot,"profiles.yaml"),"current: original\nitems: []\n");Write(Path.Combine(ConfigRoot,"verge.yaml"),"enable_tun_mode: false\n");Write(Path.Combine(ConfigRoot,"config.yaml"),"mode: rule\n");string backup=Path.Combine(folder,"backup");var info=Snapshot(backup);foreach(string rel in Managed)Write(Path.Combine(ConfigRoot,rel),"changed\n");RestoreFiles(backup,info,false);if(!File.ReadAllText(Path.Combine(ConfigRoot,"profiles.yaml")).Contains("original")||File.Exists(Path.Combine(ConfigRoot,"profiles","Lccaapp.yaml")))throw new Exception("Backup restoration failed");}finally{ConfigRoot=before;Data=oldData;}}
  public static void RunGuard(GuardRequest request){
   if(Guard.IsAdmin){Guard.Apply(request);return;}
   Directory.CreateDirectory(Data);string file=Path.Combine(Data,"guard-request-"+Guid.NewGuid().ToString("N")+".json");Write(file,Json.Serialize(request));
   try{var start=new ProcessStartInfo(Exe,"--guard "+Quote(file)){UseShellExecute=true,Verb="runas"};try{using(var p=Process.Start(start)){if(!p.WaitForExit(90000))throw new InvalidOperationException("管理员授权或系统保护操作未完成。");if(p.ExitCode!=0)throw new InvalidOperationException(File.Exists(file+".result")?File.ReadAllText(file+".result"):"系统断网保护未启用，配置操作已取消。");}}catch(System.ComponentModel.Win32Exception){throw new InvalidOperationException("未获得管理员授权，系统断网保护未启用。");}}finally{try{File.Delete(file);File.Delete(file+".result");}catch{}}
  }
  public static void Apply(Prepared prepared,bool auto,Action<string> log){
   if(!Guard.IsAdmin){Elevate(new Operation{Action="apply",Prepared=prepared,AutoStart=auto});log("配置与系统断网保护已启用。请启动或重新连接所选软件，再验证实际连接。");return;}
   RequireClash();foreach(string name in new[]{"wandou","JiuLingProxy","v2rayN"})if(Process.GetProcessesByName(name).Length>0)throw new InvalidOperationException("检测到其他代理客户端正在运行，请先退出它，避免双重代理后再应用。");
   string statePath=Path.Combine(Data,"state.json");var previous=File.Exists(statePath)?Json.Deserialize<SavedState>(File.ReadAllText(statePath)):null;
   var guarded=prepared.Paths.Concat(previous==null?new string[0]:previous.Paths).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
   Guard.Apply(new GuardRequest{Scope=Guard.Scope().ToString(),Paths=guarded,Tunnel=1});
   log("已暂时阻断所选应用，正在备份并切换配置……");string backup=Path.Combine(Data,"backups",DateTime.Now.ToString("yyyyMMdd-HHmmss")+"-"+Guid.NewGuid().ToString("N").Substring(0,6));BackupInfo b=null;bool committed=false;
   try{
    CloseClash();b=Snapshot(backup);
    Write(Path.Combine(ConfigRoot,"profiles",ProfileId+".yaml"),prepared.Yaml);
    string script="function main(config) { config.mode='rule'; config['find-process-mode']='always'; config['allow-lan']=false; config.rules="+Json.Serialize(prepared.RuleMode==2?Mode2.Rules(prepared.Paths):Rules(prepared.Paths))+"; "+(prepared.RuleMode==2?"config.sniffer="+Mode2.SnifferJson+";":"")+" return config; }";
    Write(Path.Combine(ConfigRoot,"profiles",ScriptId+".js"),script);
    var profiles=Parse(File.ReadAllText(Path.Combine(ConfigRoot,"profiles.yaml")));var items=Get(profiles,"items") as YamlSequenceNode;if(items==null)throw new InvalidOperationException("现有 Clash 订阅列表结构不支持，已取消。");
    foreach(var n in items.Children.ToArray()){var m=n as YamlMappingNode;if(m!=null&&new[]{ProfileId,ScriptId}.Contains(Str(Get(m,"uid"))))items.Children.Remove(n);}
    var item=new YamlMappingNode();Set(item,"uid",S(ProfileId));Set(item,"type",S("local"));Set(item,"name",S("应用专用代理"));Set(item,"file",S(ProfileId+".yaml"));Set(item,"option",new YamlMappingNode(S("script"),S(ScriptId)));items.Add(item);
    items.Add(new YamlMappingNode(S("uid"),S(ScriptId),S("type"),S("script"),S("name"),S("严格应用规则"),S("file"),S(ScriptId+".js")));Set(profiles,"current",S(ProfileId));Write(Path.Combine(ConfigRoot,"profiles.yaml"),Dump(profiles));
    var verge=Parse(File.ReadAllText(Path.Combine(ConfigRoot,"verge.yaml")));Set(verge,"enable_tun_mode",S("true"));Set(verge,"enable_system_proxy",S("false"));Set(verge,"enable_auto_launch",S(auto?"true":"false"));Set(verge,"enable_silent_start",S("true"));Write(Path.Combine(ConfigRoot,"verge.yaml"),Dump(verge));
    var config=Parse(File.ReadAllText(Path.Combine(ConfigRoot,"config.yaml")));Set(config,"mode",S("rule"));Set(config,"allow-lan",S("false"));var tun=Get(config,"tun") as YamlMappingNode??new YamlMappingNode();Set(tun,"enable",S("true"));Set(tun,"auto-route",S("true"));Set(tun,"strict-route",S("true"));Set(tun,"auto-detect-interface",S("true"));Set(config,"tun",tun);Write(Path.Combine(ConfigRoot,"config.yaml"),Dump(config));
    using(var run=Registry.CurrentUser.CreateSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Run")){if(auto)run.SetValue("Clash Verge",Quote(ClashExe));else run.DeleteValue("Clash Verge",false);}
    if(auto)using(var k=Registry.CurrentUser.CreateSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run")){byte[] approved=new byte[12];approved[0]=2;k.SetValue("Clash Verge",approved,RegistryValueKind.Binary);}
    using(var k=Registry.CurrentUser.CreateSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings")){k.SetValue("ProxyEnable",0,RegistryValueKind.DWord);}InternetSetOption(IntPtr.Zero,39,IntPtr.Zero,0);InternetSetOption(IntPtr.Zero,37,IntPtr.Zero,0);
    OpenClash();WaitRuntime(prepared.Paths,prepared.RuleMode);ulong luid=Tunnel();if(luid==0)throw new InvalidOperationException("未检测到 Mihomo 虚拟网卡，不能启用严格保护。");
    Write(Path.Combine(Data,"state.json"),Json.Serialize(new SavedState{Backup=backup,Paths=prepared.Paths,Scope=Guard.Scope().ToString(),ConfigRoot=ConfigRoot,HasGuard=true,RuleMode=prepared.RuleMode,TestIP=prepared.TestIP,NodeName=prepared.NodeName}));
    log("规则已就绪，正在启用系统断网保护……");RunGuard(new GuardRequest{Scope=Guard.Scope().ToString(),Paths=prepared.Paths,Tunnel=luid});committed=true;
    log("配置与系统保护已启用。请启动所选软件，再点击“验证当前连接”。");
   }catch{if(!committed){if(b!=null){CloseClash();RestoreFiles(backup,b);if(b.OldState!=null)Write(statePath,b.OldState);else if(File.Exists(statePath))File.Delete(statePath);}OpenClash();if(previous!=null&&previous.HasGuard){WaitRuntime(previous.Paths,previous.RuleMode);Guard.Apply(new GuardRequest{Scope=previous.Scope,Paths=previous.Paths,Tunnel=Tunnel()});}else Guard.Apply(new GuardRequest{Scope=Guard.Scope().ToString(),Remove=true});}throw;}
  }
  public static string Elevate(Operation operation){
   Directory.CreateDirectory(Data);string file=Path.Combine(Data,"operation-"+Guid.NewGuid().ToString("N")+".bin");byte[] payload=Encoding.UTF8.GetBytes(Json.Serialize(operation));File.WriteAllBytes(file,ProtectedData.Protect(payload,null,DataProtectionScope.CurrentUser));
   try{try{using(var p=Process.Start(new ProcessStartInfo(Exe,"--operation "+Quote(file)){UseShellExecute=true,Verb="runas"})){if(!p.WaitForExit(180000))throw new InvalidOperationException("操作尚未结束，请稍后检查状态。不要重复应用。");if(p.ExitCode!=0)throw new InvalidOperationException(File.Exists(file+".result")?File.ReadAllText(file+".result"):"操作未完成。");return File.ReadAllText(file+".result");}}catch(System.ComponentModel.Win32Exception){throw new InvalidOperationException("管理员授权被取消，操作未完成。");}}finally{try{File.Delete(file);File.Delete(file+".result");}catch{}}
  }
  public static void RemoveProtection(){if(!Guard.IsAdmin){Elevate(new Operation{Action="removeguard"});return;}Guard.Apply(new GuardRequest{Scope=Guard.Scope().ToString(),Remove=true});}
  public static void WaitRuntime(string[] paths,int ruleMode=0){Exception last=null;for(int i=0;i<15;i++){try{var c=(Dictionary<string,object>)Api("/configs");if((string)c["mode"]!="rule"||!(bool)((Dictionary<string,object>)c["tun"])["enable"])throw new Exception();var rules=(Dictionary<string,object>)Api("/rules");var a=(object[])rules["rules"];foreach(string p in paths){if(!a.Cast<Dictionary<string,object>>().Any(r=>(string)r["payload"]==p&&(string)r["proxy"]==Group)||!a.Cast<Dictionary<string,object>>().Any(r=>(string)r["payload"]==p&&(string)r["proxy"]=="REJECT"))throw new Exception();}if(ruleMode==2){foreach(string expected in Mode2.Rules(paths).Where(r=>r.StartsWith("PROCESS-"))){var parts=expected.Split(',');if(!a.Cast<Dictionary<string,object>>().Any(r=>(string)r["payload"]==parts[1]&&(string)r["proxy"]==parts[2]))throw new Exception();}if((string)((Dictionary<string,object>)a[a.Length-1])["proxy"]!="DIRECT")throw new Exception();var active=Parse(File.ReadAllText(Path.Combine(ConfigRoot,"clash-verge.yaml")));var sniff=Get(active,"sniffer") as YamlMappingNode;if(sniff==null||Str(Get(sniff,"enable"))!="true")throw new Exception();}return;}catch(Exception e){last=e;Thread.Sleep(700);}}throw new InvalidOperationException("Clash 未确认 TUN 与完整规则生效，已停止应用操作。",last);}
  public static string Verify(){
   if(!Guard.IsAdmin)return Elevate(new Operation{Action="verify"});
   string file=Path.Combine(Data,"state.json");if(!File.Exists(file))return "还没有通过本工具应用配置。";var state=Json.Deserialize<SavedState>(File.ReadAllText(file));WaitRuntime(state.Paths,state.RuleMode);int count=Guard.Count(new Guid(state.Scope));if(count==0)return "系统断网保护不存在，不能确认严格保护。请重新应用。";
   if(!Guard.AllowsTunnel(new Guid(state.Scope),Tunnel()))return "虚拟网卡标识已变化，当前保护会阻断所选应用。请重新应用配置以恢复代理通道。";
   var data=(Dictionary<string,object>)Api("/connections");var list=(object[])data["connections"];int proxy=0,direct=0;foreach(Dictionary<string,object> c in list){var m=(Dictionary<string,object>)c["metadata"];object value;if(!m.TryGetValue("processPath",out value)||!(state.RuleMode==2?Mode2.Matches(Convert.ToString(value),state.Paths):state.Paths.Contains(Convert.ToString(value),StringComparer.OrdinalIgnoreCase)))continue;var chains=(object[])c["chains"];if(chains.Any(x=>Convert.ToString(x)==Group))proxy++;else if(chains.Any(x=>Convert.ToString(x)=="DIRECT")){IPAddress address;string ip=Convert.ToString(m["destinationIP"]);if(IPAddress.TryParse(ip,out address)&&IsLocal(address))continue;direct++;}}
   return "验证时间："+DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")+"\r\n策略："+(state.RuleMode==2?Mode2.Name:"规则方式1 · 严格路径")+"；应用前出口："+state.TestIP+(state.RuleMode==2?" / "+state.NodeName:"")+"\r\nTUN 与进程规则已核对；系统保护规则 "+count+" 条。\r\n当前所选进程：代理连接 "+proxy+"，公网直连 "+direct+"。\r\n"+(direct>0?"发现异常直连，停止使用并重新应用。":proxy==0?"尚未捕获所选软件流量。请启动软件并联网后再验证。":"已捕获实际代理连接。此结果仅覆盖当前可识别进程与连接。");
  }
  static bool IsLocal(IPAddress ip){var b=ip.GetAddressBytes();return IPAddress.IsLoopback(ip)||(b.Length==4&&(b[0]==10||b[0]==192&&b[1]==168||b[0]==172&&b[1]>=16&&b[1]<=31||b[0]==169&&b[1]==254))||(b.Length==16&&((b[0]&0xfe)==0xfc||b[0]==0xfe&&(b[1]&0xc0)==0x80));}
  public static void Restore(Action<string> log){if(!Guard.IsAdmin){Elevate(new Operation{Action="restore"});log("已恢复上一次配置及相应保护状态。");return;}RequireClash();string file=Path.Combine(Data,"state.json");if(!File.Exists(file)){Guard.Apply(new GuardRequest{Scope=Guard.Scope().ToString(),Remove=true});log("没有配置备份，已解除本工具残留的系统断网保护。");return;}var state=Json.Deserialize<SavedState>(File.ReadAllText(file));if(!Path.GetFullPath(state.Backup).StartsWith(Path.GetFullPath(Path.Combine(Data,"backups"))+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("备份路径无效。");var b=Json.Deserialize<BackupInfo>(File.ReadAllText(Path.Combine(state.Backup,"snapshot.json")));Guard.Apply(new GuardRequest{Scope=state.Scope,Paths=state.Paths,Tunnel=1});CloseClash();RestoreFiles(state.Backup,b);OpenClash();
   var old=b.OldState==null?null:Json.Deserialize<SavedState>(b.OldState);if(old!=null&&old.HasGuard){WaitRuntime(old.Paths,old.RuleMode);RunGuard(new GuardRequest{Scope=old.Scope,Paths=old.Paths,Tunnel=Tunnel()});Write(file,b.OldState);}else{RunGuard(new GuardRequest{Scope=state.Scope,Remove=true});File.Delete(file);}log("已恢复上一次配置；相应的系统保护也已恢复或解除。");
  }
  [DllImport("iphlpapi.dll")]static extern uint ConvertInterfaceIndexToLuid(uint index,out ulong luid);
  [DllImport("wininet.dll",SetLastError=true)]static extern bool InternetSetOption(IntPtr h,int option,IntPtr b,int len);
 }
}
