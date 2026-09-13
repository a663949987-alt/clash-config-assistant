using System;
using System.Net;
using System.Net.Sockets;
class Probe {
 static int Main(string[] args){
  bool udp=args.Length>0&&args[0]=="udp";bool v6=args.Length>1&&args[1]=="v6";
  try{using(var s=new Socket(v6?AddressFamily.InterNetworkV6:AddressFamily.InterNetwork,udp?SocketType.Dgram:SocketType.Stream,udp?ProtocolType.Udp:ProtocolType.Tcp)){
   s.SendTimeout=6000;s.ReceiveTimeout=6000;var endpoint=new IPEndPoint(IPAddress.Parse(v6?"2606:4700:4700::1111":"1.1.1.1"),udp?53:443);var c=s.BeginConnect(endpoint,null,null);if(!c.AsyncWaitHandle.WaitOne(7000)){Console.WriteLine("TIMEOUT");return 2;}s.EndConnect(c);
   if(udp){byte[] q={0x51,0x51,1,0,0,1,0,0,0,0,0,0,7,101,120,97,109,112,108,101,3,99,111,109,0,0,1,0,1};s.Send(q);byte[] response=new byte[512];s.Receive(response);}
   Console.WriteLine("CONNECTED");return 0;
  }}catch(SocketException e){Console.WriteLine(e.NativeErrorCode==10013?"BLOCKED":"ERROR:"+e.NativeErrorCode);return e.NativeErrorCode==10013?3:2;}catch{Console.WriteLine("ERROR");return 2;}
 }
}
