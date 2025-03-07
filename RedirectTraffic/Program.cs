using System;
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
        // Examples of using PacketFilter class
        var filterTrue = PacketFilter.GetFilter(PacketFilter.FilterType.True);
        var filterIp = PacketFilter.GetFilter(PacketFilter.FilterType.Ip);
        var filterTcp = PacketFilter.GetFilter(PacketFilter.FilterType.Tcp);
        var filterPort = PacketFilter.CreatePortFilter(40000); // Source port 40000
        var customFilter = PacketFilter.CreateCustomFilter("tcp and ip.DstAddr == 192.168.1.1");

        // Use one of the filters
        var filter = filterTrue; // Change this to use a different filter

        IntPtr packetBuffer = Marshal.AllocHGlobal(1500); // Allocate buffer for packet

        try
        {
            using (var divert = new WinDivertWrapper(filter, WindivertLayer.NETWORK, 0, WindivertFlags.DROP))
            {
                WindivertAddress addr;

                while (true)
                {
                    uint recvLen;
                    if (divert.Recv(packetBuffer, 1500, out recvLen, out addr))
                    {
                        // Output packet details to the console
                        LogPacketDetails(packetBuffer, recvLen);
                    }

                    await Task.Yield(); // Yield control to keep the loop responsive
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(packetBuffer); // Ensure the allocated buffer is freed
        }
    }

    [SupportedOSPlatform("windows")]
    static unsafe void LogPacketDetails(IntPtr packet, uint packetLen)
    {
        var ethHeader = (WindivertEthhdr*)packet;
        var ipHeader = (WindivertIphdr*)(packet + sizeof(WindivertEthhdr));

        // Check if the packet is from a non-local IP
        var srcIP = new IPAddress(ipHeader->SrcAddr);
        if (!IsLocalIP(srcIP))
        {
            Console.WriteLine($"Non-local IP Packet - Src: {srcIP}, Dst: {new IPAddress(ipHeader->DstAddr)}, Protocol: {ipHeader->Protocol}, Length: {packetLen}");
        }
    }

    [SupportedOSPlatform("windows")]
    static bool IsLocalIP(IPAddress ip)
    {
        // Check for local IP ranges
        byte[] ipBytes = ip.GetAddressBytes();
        return ipBytes[0] == 10 ||
               (ipBytes[0] == 172 && (ipBytes[1] >= 16 && ipBytes[1] <= 31)) ||
               (ipBytes[0] == 192 && ipBytes[1] == 168);
    }
}
