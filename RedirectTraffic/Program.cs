using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Threading.Tasks;

class Program
{

    [SupportedOSPlatform("windows")]
    static async Task Main(string[] args)
    {
        _ = Task.Run(() => Globals.ProcessLogQueue()); // Start the log processing task

        // Primary task: Block specific IP
        await PacketFilter.BlockTrafficByPort(40000);

        // Examples of using PacketFilter class
        var filterTrue = PacketFilter.GetFilter(PacketFilter.FilterType.True);
        var filterIp = PacketFilter.GetFilter(PacketFilter.FilterType.Ip);
        var filterTcp = PacketFilter.GetFilter(PacketFilter.FilterType.Tcp);
        var filterUdp = PacketFilter.GetFilter(PacketFilter.FilterType.Udp);
        var filterTcpPort = PacketFilter.CreatePortFilter(40000); // TCP Source port 40000
        var filterUdpPort = PacketFilter.CreateUdpPortFilter(40000); // UDP Source port 40000
        var filterSourceIP = PacketFilter.CreateSourceIPFilter("192.168.1.1");
        var filterDestinationIP = PacketFilter.CreateDestinationIPFilter("192.168.1.1");
        var allowSourceIPToDestinationFromPort = PacketFilter.AllowSourceIPToDestinationFromPort("192.168.1.1", "192.168.1.2", 40000);
        var blockAllExceptSourceIP = PacketFilter.BlockAllExceptSourceIP("192.168.1.1");
        var allowOnlyToDestinationIP = PacketFilter.AllowOnlyToDestinationIP("192.168.1.2");
        var blockTrafficToPort = PacketFilter.BlockTrafficToPort(8080);
        var blockUdpTrafficToPort = PacketFilter.BlockUdpTrafficToPort(8080);
        var allowSpecificProtocol = PacketFilter.AllowSpecificProtocol("udp");
        var blockTrafficFromIPRange = PacketFilter.BlockTrafficFromIPRange("192.168.1.0/24");
        var allowOnlySecureTraffic = PacketFilter.AllowOnlySecureTraffic();
        var customFilter = PacketFilter.CreateCustomFilter("tcp and ip.DstAddr == 192.168.1.1");
        var combinedFilter = PacketFilter.CombineFilters(filterTcp, filterSourceIP);

        // Use one of the filters
        /*var filter = blockAllExceptSourceIP; // Change this to use a different filter

        IntPtr packetBuffer = Marshal.AllocHGlobal(1500); // Allocate buffer for packet

        try
        {
            using (var divert = new WinDivertWrapper(filter, WindivertLayer.NETWORK, 0, WindivertFlags.DROP))
            {
                while (true)
                {
                    uint recvLen;
                    if (divert.Recv(packetBuffer, 1500, out recvLen))
                    {
                        // Output packet details to the console
                        Globals.LogPacketDetails(packetBuffer, recvLen);
                    }

                    await Task.Yield(); // Yield control to keep the loop responsive
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(packetBuffer); // Ensure the allocated buffer is freed
        }*/
    }
}