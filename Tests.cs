using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
namespace ClashConfig {
 public static class Tests {
  static void Assert(bool value,string message){if(!value)throw new Exception(message);}
  public static void Run(string report){
   Guard.CheckLayout();string path=@"C:\Program Files\测试软件\app.exe";
   bool rejected=false;try{Core.Rules(new string[0]);}catch(InvalidOperationException){rejected=true;}Assert(rejected,"Empty selection accepted");
   var input=new Input{Kind="SOCKS5",Address="127.0.0.1:1080",Username="qa-user",Password="space: \"quote\"\ncolon: yes",Paths=new[]{path}};
   string direct=Core.Direct(input);var mapping=Core.Parse(direct);var proxies=(YamlDotNet.RepresentationModel.YamlSequenceNode)Core.Get(mapping,"proxies");var proxy=(YamlDotNet.RepresentationModel.YamlMappingNode)proxies.Children[0];Assert(Core.Str(Core.Get(proxy,"password"))==input.Password,"Credential escaping failed");
   string yaml=Core.Build(direct,input.Paths);var rules=(YamlDotNet.RepresentationModel.YamlSequenceNode)Core.Get(Core.Parse(yaml),"rules");var strings=rules.Children.Select(Core.Str).ToArray();Assert(strings.Contains("PROCESS-PATH,"+path+",Selected-Apps-Proxy"),"Missing target path");Assert(strings.Contains("PROCESS-PATH,"+path+",REJECT"),"Missing unsupported UDP fallback reject");Assert(strings.Last()=="MATCH,REJECT","Unknown process not rejected");Assert(strings.Contains("PROCESS-NAME-REGEX,^.+$,DIRECT"),"Non-target process fallback missing");
   var group=(YamlDotNet.RepresentationModel.YamlSequenceNode)Core.Get(Core.Parse(yaml),"proxy-groups");Assert(!group.ToString().Contains("DIRECT"),"Proxy group permits direct");
   input.Address="socks5://name:p%40ss@127.0.0.1:1080";input.Username=input.Password="";Core.Direct(input);
   input.Address="[::1]:1080";Core.Direct(input);
   rejected=false;try{Core.Build("proxies:\n- {name: unsafe, type: direct}\n",input.Paths);}catch(InvalidOperationException){rejected=true;}Assert(rejected,"Direct subscription node accepted");
   rejected=false;try{Core.Rules(new[]{@"C:\app,evil.exe"});}catch(InvalidOperationException){rejected=true;}Assert(rejected,"Rule injection accepted");
   var unsafeMap=Core.Parse(direct);Core.Set(unsafeMap,"external-controller",Core.S("0.0.0.0:9090"));Core.Set(unsafeMap,"tun",new YamlDotNet.RepresentationModel.YamlMappingNode(Core.S("enable"),Core.S("true")));var clean=Core.Parse(Core.Build(Core.Dump(unsafeMap),input.Paths));Assert(Core.Get(clean,"external-controller")==null&&Core.Get(clean,"tun")==null,"Untrusted inbound imported");
   string storage=Path.Combine(Path.GetDirectoryName(Path.GetFullPath(report)),"storage-test-"+Guid.NewGuid().ToString("N"));try{Core.TestStorage(storage);}finally{if(Directory.Exists(storage))Directory.Delete(storage,true);}
   File.WriteAllText(report,"PASS: x64 WFP layouts; no default selection; URL parsing; IPv6 input; credential YAML escaping; exact process routes; reject after proxy; unknown-process deny; non-target direct; direct-node and path injection rejection; subscription inbound sanitization; backup restoration of existing and originally absent files.");
  }
  static string RunProbe(string exe,string args){using(var p=Process.Start(new ProcessStartInfo(exe,args){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true})){string result=p.StandardOutput.ReadToEnd().Trim();if(!p.WaitForExit(10000)){p.Kill();throw new Exception("Probe timeout");}return result;}}
  public static void MockTest(string report){var log=new List<string>();foreach(bool socks in new[]{false,true})using(var proxy=new MockProxy(socks)){var prepared=Core.Prepare(new Input{Kind=socks?"SOCKS5":"HTTP",Address="127.0.0.1:"+proxy.Port,Username="test",Password="test",Paths=new[]{Core.Exe}},s=>{});Assert(prepared.TestIP=="203.0.113.77","Mock proxy response did not travel through Mihomo");log.Add((socks?"SOCKS5":"HTTP")+": native Mihomo validation, authenticated proxy handshake, HTTP body through proxy, exit parsing and cleanup PASS");File.WriteAllLines(report+".details",log);}File.WriteAllLines(report,log);}
  sealed class MockProxy:IDisposable{
   TcpListener listener;bool socks;volatile bool stopped;Thread accept;public int Port;
   public MockProxy(bool mode){socks=mode;listener=new TcpListener(IPAddress.Loopback,0);listener.Start();Port=((IPEndPoint)listener.LocalEndpoint).Port;accept=new Thread(()=>{while(!stopped){try{var c=listener.AcceptTcpClient();Task.Run(()=>Handle(c));}catch{if(stopped)return;}}});accept.IsBackground=true;accept.Start();}
   static byte[] Read(NetworkStream s,int n){byte[] b=new byte[n];int offset=0;while(offset<n){int count=s.Read(b,offset,n-offset);if(count==0)throw new IOException();offset+=count;}return b;}
   static string Header(NetworkStream s){var m=new MemoryStream();int a;while((a=s.ReadByte())>=0){m.WriteByte((byte)a);if(m.Length>16000)throw new IOException();var b=m.GetBuffer();int l=(int)m.Length;if(l>=4&&b[l-4]==13&&b[l-3]==10&&b[l-2]==13&&b[l-1]==10)return Encoding.ASCII.GetString(b,0,l);}return "";}
   void Handle(TcpClient c){using(c)try{c.ReceiveTimeout=4000;c.SendTimeout=4000;using(var s=c.GetStream()){
    if(socks){var first=Read(s,2);if(first[0]!=5)return;Read(s,first[1]);s.Write(new byte[]{5,2},0,2);var auth=Read(s,2);string user=Encoding.UTF8.GetString(Read(s,auth[1]));int plen=s.ReadByte();string pass=Encoding.UTF8.GetString(Read(s,plen));if(user!="test"||pass!="test")return;s.Write(new byte[]{1,0},0,2);var connect=Read(s,4);if(connect[1]!=1)return;if(connect[3]==1)Read(s,4);else if(connect[3]==4)Read(s,16);else if(connect[3]==3)Read(s,s.ReadByte());else return;var p=Read(s,2);int port=p[0]*256+p[1];s.Write(new byte[]{5,0,0,1,127,0,0,1,0,0},0,10);if(port==443)return;Header(s);
    }else{string h=Header(s);if(h.IndexOf("Proxy-Authorization: Basic dGVzdDp0ZXN0",StringComparison.OrdinalIgnoreCase)<0){byte[] error=Encoding.ASCII.GetBytes("HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");s.Write(error,0,error.Length);return;}if(h.StartsWith("CONNECT")){byte[] ok=Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n");s.Write(ok,0,ok.Length);if(h.Split('\r')[0].Contains(":443"))return;Header(s);}}
    string body="Current IP: 203.0.113.77";byte[] response=Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "+body.Length+"\r\nConnection: close\r\n\r\n"+body);s.Write(response,0,response.Length);
   }}catch{}}
   public void Dispose(){stopped=true;listener.Stop();accept.Join(1000);}
  }
  public static void GuardTest(string report){
   if(!Guard.IsAdmin)throw new InvalidOperationException("Guard test requires administrator approval.");if(Guard.Count(Guard.Scope())!=0)throw new InvalidOperationException("Existing app protection is active; test refused.");
   string folder=Path.Combine(Path.GetDirectoryName(Path.GetFullPath(report)),"guard-test-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(folder);string target=Path.Combine(folder,"ClashGuardProbe.exe"),control=Path.Combine(folder,"ClashControlProbe.exe");var log=new List<string>();
   using(var stream=Assembly.GetExecutingAssembly().GetManifestResourceStream("ClashGuardProbe.exe"))using(var output=File.Create(target)){stream.CopyTo(output);}File.Copy(target,control);
   try{
    string baseline=RunProbe(target,"");log.Add("TCP baseline: "+baseline);Assert(baseline=="CONNECTED","Baseline public connection unavailable; test inconclusive");
    string udpBase=RunProbe(target,"udp");log.Add("UDP baseline: "+udpBase);
    ulong currentTun=Core.Tunnel();Assert(currentTun!=0,"No active Mihomo TUN for positive-path test");Guard.Apply(new GuardRequest{Scope=Guard.Scope().ToString(),Paths=new[]{target},Tunnel=currentTun});Assert(Guard.AllowsTunnel(Guard.Scope(),currentTun),"Live guard identity check failed");string throughTun=RunProbe(target,"");log.Add("Current TUN allowed: "+throughTun);Assert(throughTun=="CONNECTED","WFP did not allow current TUN");
    Guard.Apply(new GuardRequest{Scope=Guard.Scope().ToString(),Paths=new[]{target},Tunnel=1});
    Assert(!Guard.AllowsTunnel(Guard.Scope(),currentTun),"Stale tunnel was incorrectly considered protected and available");
    Assert(Guard.Count(Guard.Scope())==12,"Unexpected filter count");string blocked=RunProbe(target,"");log.Add("TCP bypass with guard: "+blocked);Assert(blocked=="BLOCKED","WFP did not block public TCP");
    string udp=RunProbe(target,"udp");log.Add("UDP bypass with guard: "+udp);Assert(udp=="BLOCKED"||(udpBase=="CONNECTED"&&(udp=="TIMEOUT"||udp=="ERROR:10060")),"UDP test inconclusive: baseline="+udpBase+", guard="+udp);
    string other=RunProbe(control,"");log.Add("Non-target TCP: "+other);Assert(other=="CONNECTED","Non-target app was affected");
    Guard.Apply(new GuardRequest{Scope=Guard.Scope().ToString(),Remove=true});Assert(Guard.Count(Guard.Scope())==0,"Guard filters remain");string after=RunProbe(target,"");log.Add("TCP after removal: "+after);Assert(after=="CONNECTED","Connection not restored");
    log.Add("PASS: persistent IPv4+IPv6 filters installed and removed; current TUN allowed; live IPv4 TCP and UDP blocked when allowed TUN is unavailable; non-target process unaffected. Live IPv6 and full OS restart remain untested.");File.WriteAllLines(report,log);
   }finally{Guard.Apply(new GuardRequest{Scope=Guard.Scope().ToString(),Remove=true});foreach(string f in new[]{target,control})if(File.Exists(f))File.Delete(f);Directory.Delete(folder);File.WriteAllLines(report+".details",log);if(!File.Exists(report))File.WriteAllLines(report,log);}
  }
 }
}
