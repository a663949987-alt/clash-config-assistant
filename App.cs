using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;

[assembly:AssemblyTitle("Clash 应用代理配置助手")]
[assembly:AssemblyVersion("1.1.1.0")]
namespace ClashConfig {
 public sealed class MainForm:Form {
  ComboBox kind;TextBox address,user,password;CheckBox show,auto;ListView apps;Label count,status,client;Button apply,verify,restore,test;FlowLayoutPanel commandBar;bool busy;
  public MainForm(){
   Text="Clash 应用代理配置助手";Font=new Font("Microsoft YaHei UI",10);AutoScaleMode=AutoScaleMode.Dpi;ClientSize=new Size(800,780);MinimumSize=new Size(760,740);StartPosition=FormStartPosition.CenterScreen;BackColor=Color.FromArgb(244,247,251);
   var root=new TableLayoutPanel{Dock=DockStyle.Fill,Padding=new Padding(18,12,18,12),ColumnCount=1,RowCount=7};root.RowStyles.Add(new RowStyle(SizeType.Absolute,44));root.RowStyles.Add(new RowStyle(SizeType.Absolute,36));root.RowStyles.Add(new RowStyle(SizeType.Absolute,162));root.RowStyles.Add(new RowStyle(SizeType.Percent,100));root.RowStyles.Add(new RowStyle(SizeType.Absolute,76));root.RowStyles.Add(new RowStyle(SizeType.Absolute,50));root.RowStyles.Add(new RowStyle(SizeType.Absolute,70));Controls.Add(root);
   var title=new Label{Text="选择应用，专用代理",Font=new Font(Font.FontFamily,21,FontStyle.Bold),AutoSize=true,Dock=DockStyle.Fill,ForeColor=Color.FromArgb(25,43,67)};root.Controls.Add(title,0,0);
   var clientRow=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=2};clientRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));clientRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,150));client=new Label{Text=Core.ClashExe==null?"尚未发现 Clash Verge Rev":"已发现 Clash Verge Rev · 严格模式",AutoSize=true,Dock=DockStyle.Fill,TextAlign=ContentAlignment.MiddleLeft};var locate=new Button{Text="选择 Clash 客户端",Dock=DockStyle.Fill,FlatStyle=FlatStyle.Flat};locate.Click+=delegate{using(var dlg=new OpenFileDialog{Title="选择 clash-verge.exe",Filter="Clash Verge|clash-verge.exe"})if(dlg.ShowDialog(this)==DialogResult.OK){using(var k=Registry.CurrentUser.CreateSubKey("Software\\ClashConfigAssistant"))k.SetValue("ClashPath",dlg.FileName);client.Text="已选择 Clash Verge Rev";}};clientRow.Controls.Add(client,0,0);clientRow.Controls.Add(locate,1,0);root.Controls.Add(clientRow,0,1);
   var proxy=new GroupBox{Text="1  填写代理",Dock=DockStyle.Fill,Padding=new Padding(14,12,14,10)};var fields=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=4,RowCount=3};fields.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,105));fields.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,145));fields.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,85));fields.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
   kind=new ComboBox{DropDownStyle=ComboBoxStyle.DropDownList,Dock=DockStyle.Fill};kind.Items.AddRange(new object[]{"Clash 订阅","SOCKS5","HTTP"});kind.SelectedIndex=0;address=new TextBox{Dock=DockStyle.Fill,UseSystemPasswordChar=true,AccessibleName="代理地址或订阅链接"};user=new TextBox{Dock=DockStyle.Fill,AccessibleName="代理账号"};password=new TextBox{Dock=DockStyle.Fill,UseSystemPasswordChar=true,AccessibleName="代理密码"};show=new CheckBox{Text="显示地址",AutoSize=true,Dock=DockStyle.Fill};show.CheckedChanged+=delegate{address.UseSystemPasswordChar=!show.Checked;};
   fields.Controls.Add(Label("类型"),0,0);fields.Controls.Add(kind,1,0);fields.Controls.Add(Label("地址"),2,0);fields.Controls.Add(address,3,0);fields.Controls.Add(Label("账号"),0,1);fields.Controls.Add(user,1,1);fields.Controls.Add(Label("密码"),2,1);fields.Controls.Add(password,3,1);fields.Controls.Add(show,0,2);fields.SetColumnSpan(show,2);var hint=Label("订阅填 HTTPS 链接；普通代理填主机:端口。");hint.ForeColor=Color.DimGray;fields.Controls.Add(hint,2,2);fields.SetColumnSpan(hint,2);kind.SelectedIndexChanged+=delegate{user.Enabled=password.Enabled=kind.SelectedIndex!=0;};user.Enabled=password.Enabled=false;proxy.Controls.Add(fields);root.Controls.Add(proxy,0,2);
   var programs=new GroupBox{Text="2  选择走代理的软件（默认不选）",Dock=DockStyle.Fill,Padding=new Padding(14,12,14,10)};var listLayout=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=1,RowCount=2};listLayout.RowStyles.Add(new RowStyle(SizeType.Percent,100));listLayout.RowStyles.Add(new RowStyle(SizeType.Absolute,38));apps=new ListView{Dock=DockStyle.Fill,View=View.Details,CheckBoxes=true,FullRowSelect=true,HideSelection=false};apps.Columns.Add("软件",220);apps.Columns.Add("包含的 EXE / 联网组件",500);apps.ItemChecked+=delegate{UpdateCount();};listLayout.Controls.Add(apps,0,0);
   var addRow=new FlowLayoutPanel{Dock=DockStyle.Fill};var browse=new Button{Text="添加 EXE…",Width=120,Height=31};browse.Click+=delegate{using(var dlg=new OpenFileDialog{Filter="应用程序 (*.exe)|*.exe",Multiselect=true,Title="选择需要走代理的程序及其联网组件"})if(dlg.ShowDialog(this)==DialogResult.OK)foreach(string p in dlg.FileNames)AddChoice(new Choice{Name=Path.GetFileNameWithoutExtension(p),Paths=new[]{p}});};var running=new Button{Text="刷新运行软件",Width=180,Height=31};running.Click+=delegate{LoadRunningChoices();};count=Label("已选 0 个应用");count.AutoSize=true;addRow.Controls.Add(browse);addRow.Controls.Add(running);addRow.Controls.Add(count);listLayout.Controls.Add(addRow,0,1);programs.Controls.Add(listLayout);root.Controls.Add(programs,0,3);
   root.RowStyles[4]=new RowStyle(SizeType.Absolute,100);
   var safety=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=1,RowCount=2};safety.RowStyles.Add(new RowStyle(SizeType.Absolute,34));safety.RowStyles.Add(new RowStyle(SizeType.Percent,100));auto=new CheckBox{Text="Clash 随 Windows 登录启动并保持此模式",Checked=true,AutoSize=true,Dock=DockStyle.Fill};safety.Controls.Add(auto,0,0);safety.Controls.Add(new Label{Text="严格保护需管理员授权；代理故障不回退。仅局域网保留直连。\n请纳入软件的全部联网 EXE；程序更新换路径后须重新应用。",AutoSize=true,Dock=DockStyle.Fill,ForeColor=Color.FromArgb(125,80,24)},0,1);root.Controls.Add(safety,0,4);
   commandBar=new FlowLayoutPanel{Dock=DockStyle.Fill,WrapContents=false};apply=Button("一键应用＋断网保护",230,true);test=Button("仅检查代理",130,false);verify=Button("验证当前连接",145,false);restore=Button("还原上次配置",145,false);commandBar.Controls.AddRange(new Control[]{apply,test,verify,restore});root.Controls.Add(commandBar,0,5);
   safety.RowCount=3;safety.RowStyles[0]=new RowStyle(SizeType.Absolute,30);safety.RowStyles[1]=new RowStyle(SizeType.Absolute,48);safety.RowStyles.Add(new RowStyle(SizeType.Percent,100));var recovery=new LinkLabel{Text="故障恢复：只解除本工具的系统断网保护",Dock=DockStyle.Fill,AutoSize=true};safety.Controls.Add(recovery,0,2);recovery.LinkClicked+=async delegate{if(MessageBox.Show(this,"解除后，Clash 退出时这些程序可能恢复直连。确定只解除本工具的系统保护？","故障恢复",MessageBoxButtons.YesNo,MessageBoxIcon.Warning)!=DialogResult.Yes)return;await Execute(async()=>{await Task.Run(()=>Core.RemoveProtection());Log("系统断网保护已解除。Clash 配置未改变；需要严格保护时请重新应用。");});};
   status=new Label{Text="准备就绪。填写地址并选择应用；切换时所选程序会短暂断网。",Dock=DockStyle.Fill,AutoSize=false,BackColor=Color.White,Padding=new Padding(12),ForeColor=Color.FromArgb(45,60,80)};root.Controls.Add(status,0,6);
   apply.Click+=async delegate{await Execute(async()=>{Input input=ReadInput();var prepared=await Task.Run(()=>Core.Prepare(input,Log));await Task.Run(()=>Core.Apply(prepared,input.AutoStart,Log));try{LocalMemory.Save(input);}catch{Log("代理与保护已应用，但本机记忆保存失败。下次需要重新填写。");}});};
   test.Click+=async delegate{await Execute(async()=>{Input input=ReadInput();await Task.Run(()=>Core.Prepare(input,Log));Log("代理出口测试成功。此操作未修改 Clash，也没有启用断网保护。");});};
   verify.Click+=async delegate{await Execute(async()=>Log(await Task.Run(()=>Core.Verify())));};
   restore.Click+=async delegate{if(MessageBox.Show(this,"恢复上一次应用前的 Clash 配置，并相应恢复或解除本工具的系统断网保护？","还原配置",MessageBoxButtons.YesNo,MessageBoxIcon.Question)!=DialogResult.Yes)return;await Execute(()=>Task.Run(()=>Core.Restore(Log)));};
   FormClosing+=delegate(object sender,FormClosingEventArgs e){if(busy){e.Cancel=true;Log("操作进行中，请等待完成后再关闭。");}};
   LoadChoices();LoadRunningChoices();
   root.RowStyles[2]=new RowStyle(SizeType.Absolute,184);fields.RowCount=4;
   var memoryBar=new FlowLayoutPanel{Dock=DockStyle.Fill,WrapContents=false};
   var saveMemory=new Button{Text="记住当前填写",Width=145,Height=32};var useApps=new Button{Text="恢复上次应用选择",Width=175,Height=32};var clearMemory=new Button{Text="清除记忆",Width=110,Height=32};memoryBar.Controls.AddRange(new Control[]{saveMemory,useApps,clearMemory});fields.Controls.Add(memoryBar,0,3);fields.SetColumnSpan(memoryBar,4);
   saveMemory.Click+=delegate{try{SaveMemory();Log("已加密记住代理、开机选项和应用选择。下次打开不会自动应用网络设置。");}catch{Log("本机记忆保存失败，原记忆未主动清除。");}};
   useApps.Click+=delegate{try{var saved=LocalMemory.Load();if(saved==null){Log("尚无本机记忆。");return;}foreach(ListViewItem item in apps.Items)item.Checked=false;foreach(string p in saved.Paths??new string[0])AddChoice(new Choice{Name=Path.GetFileNameWithoutExtension(p),Paths=new[]{p}});foreach(ListViewItem item in apps.Items)item.Checked=((Choice)item.Tag).Paths.All(p=>(saved.Paths??new string[0]).Contains(p,StringComparer.OrdinalIgnoreCase));Log("已恢复仍存在的应用路径。软件更新后，请补充新增的联网组件，再点击应用。");}catch{Log("无法读取本机记忆，请重新填写或清除记忆。");}};
   clearMemory.Click+=delegate{try{LocalMemory.Clear();address.Clear();user.Clear();password.Clear();foreach(ListViewItem item in apps.Items)item.Checked=false;Log("已清除本机表单记忆。已生效的 Clash 配置与保护规则不受影响。");}catch{Log("清除记忆失败，请检查文件权限。");}};
   try{var saved=LocalMemory.Load();if(saved!=null){if(kind.Items.Contains(saved.Kind))kind.SelectedItem=saved.Kind;address.Text=saved.Address??"";user.Text=saved.Username??"";password.Text=saved.Password??"";auto.Checked=saved.AutoStart;status.Text="已读取本机加密记忆。应用仍未勾选；可手动选择或恢复上次选择。";}}catch{status.Text="本机记忆无法解密，未加载。可重新填写或清除记忆。";}
  }
  void SaveMemory(){LocalMemory.Save(new Input{Kind=kind.Text,Address=address.Text.Trim(),Username=user.Text,Password=password.Text,AutoStart=auto.Checked,Paths=apps.CheckedItems.Cast<ListViewItem>().SelectMany(x=>((Choice)x.Tag).Paths).Distinct(StringComparer.OrdinalIgnoreCase).ToArray()});}
  Label Label(string t){return new Label{Text=t,Dock=DockStyle.Fill,TextAlign=ContentAlignment.MiddleLeft,AutoSize=true};}
  Button Button(string t,int w,bool primary){return new Button{Text=t,Width=w,Height=42,FlatStyle=FlatStyle.Flat,BackColor=primary?Color.FromArgb(35,101,211):Color.White,ForeColor=primary?Color.White:Color.FromArgb(40,55,75)};}
  void Log(string s){if(IsDisposed)return;if(InvokeRequired){BeginInvoke(new Action<string>(Log),s);return;}status.Text=s;}
  async Task Execute(Func<Task> task){if(busy)return;busy=true;commandBar.Enabled=false;try{await task();}catch(Exception e){Log(e is InvalidOperationException?e.Message:"操作未完成（"+e.GetType().Name+"）。请检查客户端状态后重试。");}finally{busy=false;commandBar.Enabled=true;}}
  Input ReadInput(){var paths=apps.CheckedItems.Cast<ListViewItem>().SelectMany(x=>((Choice)x.Tag).Paths).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();if(paths.Length==0)throw new InvalidOperationException("请至少选择一个应用，每次需由你自己勾选。");if(String.IsNullOrWhiteSpace(address.Text))throw new InvalidOperationException("请填写代理地址或订阅链接。");return new Input{Kind=kind.Text,Address=address.Text.Trim(),Username=user.Text,Password=password.Text,AutoStart=auto.Checked,Paths=paths};}
  void UpdateCount(){if(count!=null){if(IsHandleCreated)BeginInvoke(new Action(()=>count.Text="已选 "+apps.CheckedItems.Count+" 个应用"));else count.Text="已选 "+apps.CheckedItems.Count+" 个应用";}}
  void AddChoice(Choice c){c.Paths=c.Paths.Where(File.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();if(c.Paths.Length==0||apps.Items.Cast<ListViewItem>().Any(i=>((Choice)i.Tag).Paths.SequenceEqual(c.Paths,StringComparer.OrdinalIgnoreCase)))return;var item=new ListViewItem(c.Name){Tag=c,Checked=false};item.SubItems.Add(String.Join("、",c.Paths.Select(Path.GetFileName)));apps.Items.Add(item);}
  void LoadRunningChoices(){
   var paths=new HashSet<string>(apps.Items.Cast<ListViewItem>().SelectMany(i=>((Choice)i.Tag).Paths),StringComparer.OrdinalIgnoreCase);
   foreach(var p in Process.GetProcesses()){
    try{if(p.MainWindowHandle==IntPtr.Zero||p.Id==Process.GetCurrentProcess().Id||p.ProcessName=="clash-verge")continue;string path=p.MainModule.FileName;if(!paths.Add(path))continue;string name=FileVersionInfo.GetVersionInfo(path).FileDescription;AddChoice(new Choice{Name=String.IsNullOrWhiteSpace(name)?p.ProcessName:name,Paths=new[]{path}});}catch{}finally{p.Dispose();}
   }
  }
  void LoadChoices(){
   foreach(string root in new[]{Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)}){AddChoice(new Choice{Name="Microsoft Edge",Paths=new[]{Path.Combine(root,"Microsoft","Edge","Application","msedge.exe")}});AddChoice(new Choice{Name="Google Chrome",Paths=new[]{Path.Combine(root,"Google","Chrome","Application","chrome.exe")}});}
   var phones=new List<string>();string packages=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"WindowsApps");try{foreach(string pattern in new[]{"Microsoft.YourPhone_*_x64__*","MicrosoftWindows.CrossDevice_*_x64__*"})foreach(string dir in Directory.GetDirectories(packages,pattern))foreach(string f in Directory.GetFiles(dir,"*.exe"))if(Path.GetFileName(f)!="createdump.exe")phones.Add(f);}catch{}
   AddChoice(new Choice{Name="手机连接（含跨设备组件）",Paths=phones.ToArray()});
   if(phones.Count==0){using(var packagesKey=Registry.CurrentUser.OpenSubKey(@"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages")){if(packagesKey!=null)foreach(string key in packagesKey.GetSubKeyNames().Where(k=>k.StartsWith("Microsoft.YourPhone_")||k.StartsWith("MicrosoftWindows.CrossDevice_")))using(var sub=packagesKey.OpenSubKey(key)){string dir=sub.GetValue("PackageRootFolder") as string;if(dir!=null)foreach(string name in new[]{"PhoneExperienceHost.exe","YourPhoneAppProxy.exe","YourPhoneAppProxyHost.exe","CrossDeviceService.exe"}){string p=Path.Combine(dir,name);if(File.Exists(p))phones.Add(p);}}}AddChoice(new Choice{Name="手机连接（含跨设备组件）",Paths=phones.ToArray()});}
   foreach(string name in new[]{"DingTalk","WXWork","WeChat","Weixin","QQ"}){var paths=new List<string>();foreach(var p in Process.GetProcessesByName(name)){try{paths.Add(p.MainModule.FileName);}catch{}finally{p.Dispose();}}AddChoice(new Choice{Name=name=="WXWork"?"企业微信":name=="DingTalk"?"钉钉":name,Paths=paths.ToArray()});}
  }
 }
 public static class Program {
  [STAThread] public static int Main(string[] args){
   AppDomain.CurrentDomain.AssemblyResolve+=(sender,e)=>{if(new AssemblyName(e.Name).Name!="YamlDotNet")return null;using(var s=Assembly.GetExecutingAssembly().GetManifestResourceStream("YamlDotNet.dll")){var b=new byte[s.Length];s.Read(b,0,b.Length);return Assembly.Load(b);}};
   return Run(args);
  }
  [MethodImpl(MethodImplOptions.NoInlining)]static int Run(string[] args){
   System.Net.ServicePointManager.SecurityProtocol=System.Net.SecurityProtocolType.Tls12;
   if(args.Length==2&&args[0]=="--operation"){try{var operation=Core.Json.Deserialize<Operation>(System.Text.Encoding.UTF8.GetString(System.Security.Cryptography.ProtectedData.Unprotect(File.ReadAllBytes(args[1]),null,System.Security.Cryptography.DataProtectionScope.CurrentUser)));string result="OK";if(operation.Action=="apply")Core.Apply(operation.Prepared,operation.AutoStart,s=>{});else if(operation.Action=="restore")Core.Restore(s=>{});else if(operation.Action=="removeguard")Core.RemoveProtection();else if(operation.Action=="verify")result=Core.Verify();else if(operation.Action=="guardstatus")result=Guard.Count(Guard.Scope()).ToString();else throw new InvalidOperationException("操作无效。");File.WriteAllText(args[1]+".result",result);return 0;}catch(Exception e){File.WriteAllText(args[1]+".result",e is InvalidOperationException?e.Message:e.GetType().Name);return 1;}}
   if(args.Length==2&&args[0]=="--memory-test"){try{LocalMemory.Test(args[1]);return 0;}catch(Exception e){File.WriteAllText(args[1],e.ToString());return 1;}}
   if(args.Length==2&&args[0]=="--guard"){try{Guard.Apply(Core.Json.Deserialize<GuardRequest>(File.ReadAllText(args[1])));File.WriteAllText(args[1]+".result","OK");return 0;}catch(Exception e){File.WriteAllText(args[1]+".result",e is InvalidOperationException?e.Message:e.GetType().Name);return 1;}}
   if(args.Length==2&&args[0]=="--self-test"){try{Tests.Run(args[1]);return 0;}catch(Exception e){File.WriteAllText(args[1],e.ToString());return 1;}}
   if(args.Length==2&&args[0]=="--guard-test"){try{Tests.GuardTest(args[1]);return 0;}catch(Exception e){File.WriteAllText(args[1],e.ToString());return 1;}}
   if(args.Length==2&&args[0]=="--core-test"){try{Tests.MockTest(args[1]);return 0;}catch(Exception e){File.WriteAllText(args[1],e.ToString());return 1;}}
   bool created;using(var m=new Mutex(true,"Local\\ClashConfigAssistant.UI",out created)){if(!created)return 0;Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);Application.Run(new MainForm());}return 0;
  }
 }
}
