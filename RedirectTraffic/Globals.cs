using System.Collections.Concurrent;
using System.Net;
using System.Runtime.Versioning;

public static class Globals
{
    public static readonly ConcurrentQueue<string> LogQueue = new ConcurrentQueue<string>();

    public static void ProcessLogQueue()
    {
        while (true)
        {
            while (LogQueue.TryDequeue(out var logMessage))
            {
                Console.WriteLine(logMessage);
            }

            // Small sleep to avoid busy waiting
            System.Threading.Thread.Sleep(50);
        }
    }

    [SupportedOSPlatform("windows")]
    public static unsafe void LogPacketDetails(IntPtr packet, uint packetLen)
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
    public static bool IsLocalIP(IPAddress ip)
    {
        // Check for local IP ranges
        byte[] ipBytes = ip.GetAddressBytes();
        return ipBytes[0] == 10 ||
               (ipBytes[0] == 172 && (ipBytes[1] >= 16 && ipBytes[1] <= 31)) ||
               (ipBytes[0] == 192 && ipBytes[1] == 168);
    }
}