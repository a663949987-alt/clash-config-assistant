using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using YamlDotNet.RepresentationModel;

namespace ClashConfig {
 public static class Mode2 {
  public const string Name="规则方式2 · 应用兼容";
  public const string SnifferJson="{\"enable\":true,\"force-dns-mapping\":true,\"parse-pure-ip\":true,\"override-destination\":true,\"sniff\":{\"HTTP\":{\"ports\":[80,\"8080-8880\"]},\"TLS\":{\"ports\":[443,8443]},\"QUIC\":{\"ports\":[443,8443]}}}";
  public static string SelectNode(string raw,string name){
   if(String.IsNullOrWhiteSpace(name))return raw;
   var root=Core.Parse(raw);var nodes=Core.Get(root,"proxies") as YamlSequenceNode;
   if(nodes==null)throw new InvalidOperationException("订阅不含 proxies。");
   var matches=nodes.Children.OfType<YamlMappingNode>().Where(n=>Core.Str(Core.Get(n,"name"))==name.Trim()).ToArray();
   if(matches.Length!=1)throw new InvalidOperationException("固定节点名称未唯一匹配，已停止。不会自动选择其他节点。");
   Core.Set(root,"proxies",new YamlSequenceNode(matches[0]));return Core.Dump(root);
  }  public static string DouyinRoot(string p){
   string marker=Path.DirectorySeparatorChar+"ByteDance"+Path.DirectorySeparatorChar+"douyin"+Path.DirectorySeparatorChar;
   int pos=p.IndexOf(marker,StringComparison.OrdinalIgnoreCase);return pos<0?null:p.Substring(0,pos+marker.Length-1);
  }
  public static string[] Expand(string[] paths){
   var all=new HashSet<string>(paths,StringComparer.OrdinalIgnoreCase);
   foreach(string root in paths.Select(DouyinRoot).Where(p=>p!=null).Distinct(StringComparer.OrdinalIgnoreCase)){
    var pending=new Stack<string>();pending.Push(root);int count=0;
    while(pending.Count>0){string dir=pending.Pop();if((File.GetAttributes(dir)&FileAttributes.ReparsePoint)!=0)continue;if(++count>500)throw new InvalidOperationException("抖音目录过大，请检查安装路径。");foreach(string file in Directory.GetFiles(dir,"*.exe"))all.Add(file);foreach(string sub in Directory.GetDirectories(dir))pending.Push(sub);}
   }return all.OrderBy(p=>p,StringComparer.OrdinalIgnoreCase).ToArray();
  }
  public static List<string> Rules(string[] paths){
   var list=Core.Rules(paths);int start=list.FindIndex(r=>r.StartsWith("PROCESS-NAME,"));list.RemoveRange(start,list.Count-start);
   foreach(string root in paths.Select(DouyinRoot).Where(p=>p!=null).Distinct(StringComparer.OrdinalIgnoreCase)){list.Add("PROCESS-PATH-WILDCARD,"+root+"\\*,"+Core.Group);list.Add("PROCESS-PATH-WILDCARD,"+root+"\\*,REJECT");}
   if(paths.Any(p=>DouyinRoot(p)!=null||Path.GetFileName(p).IndexOf("douyin",StringComparison.OrdinalIgnoreCase)>=0)){list.Add("PROCESS-NAME-WILDCARD,*douyin*,"+Core.Group);list.Add("PROCESS-NAME-WILDCARD,*douyin*,REJECT");}
   foreach(string name in paths.Select(Path.GetFileName).Distinct(StringComparer.OrdinalIgnoreCase)){list.Add("PROCESS-NAME,"+name+","+Core.Group);list.Add("PROCESS-NAME,"+name+",REJECT");}
   list.Add("MATCH,DIRECT");return list;
  }
  public static bool Matches(string path,string[] paths){return paths.Contains(path,StringComparer.OrdinalIgnoreCase)||paths.Select(Path.GetFileName).Contains(Path.GetFileName(path),StringComparer.OrdinalIgnoreCase)||paths.Any(p=>DouyinRoot(p)!=null&&path.StartsWith(DouyinRoot(p)+"\\",StringComparison.OrdinalIgnoreCase))||(paths.Any(p=>DouyinRoot(p)!=null||Path.GetFileName(p).IndexOf("douyin",StringComparison.OrdinalIgnoreCase)>=0)&&Path.GetFileName(path).IndexOf("douyin",StringComparison.OrdinalIgnoreCase)>=0);}
 }
}
