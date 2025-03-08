using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

public class PacketFilter
{
    // Enum for predefined filters
    public enum FilterType
    {
        True,
        Ip,
        Tcp,
        Udp
    }

    /// <summary>
    /// Get predefined filters based on the specified filter type.
    /// </summary>
    /// <param name="filterType">The type of filter to retrieve.</param>
    /// <returns>The filter expression as a string.</returns>
    public static string GetFilter(FilterType filterType)
    {
        return filterType switch
        {
            FilterType.True => "true",
            FilterType.Ip => "ip",
            FilterType.Tcp => "tcp",
            FilterType.Udp => "udp",
            _ => throw new ArgumentException("Invalid filter type")
        };
    }

    /// <summary>
    /// Create a filter for a specific TCP port.
    /// </summary>
    /// <param name="port">The port number to filter.</param>
    /// <param name="isSourcePort">Whether to filter the source port.</param>
    /// <returns>The filter expression as a string.</returns>
    public static string CreatePortFilter(int port, bool isSourcePort = true)
    {
        return isSourcePort ? $"tcp.SrcPort == {port}" : $"tcp.DstPort == {port}";
    }

    /// <summary>
    /// Create a filter for a specific UDP port.
    /// </summary>
    /// <param name="port">The port number to filter.</param>
    /// <param name="isSourcePort">Whether to filter the source port.</param>
    /// <returns>The filter expression as a string.</returns>
    public static string CreateUdpPortFilter(int port, bool isSourcePort = true)
    {
        return isSourcePort ? $"udp.SrcPort == {port}" : $"udp.DstPort == {port}";
    }

    /// <summary>
    /// Create a filter for a specific source IP address.
    /// </summary>
    /// <param name="ip">The source IP address to filter.</param>
    /// <returns>The filter expression as a string.</returns>
    public static string CreateSourceIPFilter(string ip)
    {
        return $"ip.SrcAddr == {ip}";
    }

    /// <summary>
    /// Create a filter for a specific destination IP address.
    /// </summary>
    /// <param name="ip">The destination IP address to filter.</param>
    /// <returns>The filter expression as a string.</returns>
    public static string CreateDestinationIPFilter(string ip)
    {
        return $"ip.DstAddr == {ip}";
    }

    // Additional filter methods for various scenarios
    public static string AllowSourceIPToDestinationFromPort(string sourceIP, string destinationIP, int port)
    {
        return $"ip.SrcAddr == {sourceIP} and ip.DstAddr == {destinationIP} and tcp.SrcPort == {port}";
    }

    public static string BlockAllExceptSourceIP(string sourceIP)
    {
        return $"not ip.SrcAddr == {sourceIP}";
    }

    public static string AllowOnlyToDestinationIP(string destinationIP)
    {
        return $"ip.DstAddr == {destinationIP}";
    }

    public static string BlockTrafficToPort(int port)
    {
        return $"not tcp.DstPort == {port}";
    }

    public static string BlockUdpTrafficToPort(int port)
    {
        return $"not udp.DstPort == {port}";
    }

    public static string AllowSpecificProtocol(string protocol)
    {
        return $"{protocol}";
    }

    public static string BlockTrafficFromIPRange(string ipRange)
    {
        return $"not ip.SrcAddr == {ipRange}";
    }

    public static string AllowOnlySecureTraffic()
    {
        return $"tcp.DstPort == 443";
    }

    /// <summary>
    /// Combine multiple filter expressions into a single expression.
    /// </summary>
    /// <param name="filters">An array of filter expressions to combine.</param>
    /// <returns>The combined filter expression as a string.</returns>
    public static string CombineFilters(params string[] filters)
    {
        return string.Join(" and ", filters);
    }

    /// <summary>
    /// Create a custom filter expression.
    /// </summary>
    /// <param name="filterExpression">The custom filter expression.</param>
    /// <returns>The filter expression as a string.</returns>
    public static string CreateCustomFilter(string filterExpression)
    {
        return filterExpression;
    }

    /// <summary>
    /// Continuously block traffic from the specified IP address.
    /// </summary>
    /// <param name="ip">The IP address to block.</param>
    public static async Task BlockAllTraffic(string ip)
    {
        IntPtr packetBuffer = Marshal.AllocHGlobal(1500); // Allocate buffer for packet

        try
        {
            // Using a filter to block all traffic from the specified IP
            using (var divert = new WinDivertWrapper($"ip.SrcAddr == {ip} or ip.DstAddr == {ip}", WindivertLayer.NETWORK, 0, WindivertFlags.DROP))
            {
                // Enqueue log message for start of blocking
                Globals.LogQueue.Enqueue($"Blocking all traffic for IP: {ip}");

                while (true)
                {
                    uint recvLen;
                    if (divert.Recv(packetBuffer, 1500, out recvLen))
                    {
                        // Log the blocked packet details
                        unsafe
                        {
                            var tcpHeader = (WindivertTcphdr*)(packetBuffer + sizeof(WindivertEthhdr) + sizeof(WindivertIphdr));
                            if (tcpHeader->Syn && !tcpHeader->Ack)
                            {
                                Globals.LogQueue.Enqueue($"Intercepted and blocked SYN packet from {ip}. Length: {recvLen}");
                            }
                            else if (tcpHeader->Syn && tcpHeader->Ack)
                            {
                                Globals.LogQueue.Enqueue($"Intercepted and blocked SYN-ACK packet from {ip}. Length: {recvLen}");
                            }
                            else
                            {
                                Globals.LogQueue.Enqueue($"Intercepted and blocked packet from {ip}. Length: {recvLen}");
                            }
                        }
                    }
                    else
                    {
                        // Enqueue error log message
                        int error = Marshal.GetLastWin32Error();
                        if (error != 0)
                        {
                            Globals.LogQueue.Enqueue($"Failed to receive packet for blocking. Error: {error}");
                        }
                    }

                    // Prevent high CPU usage
                    await Task.Yield();
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(packetBuffer); // Ensure the allocated buffer is freed
            Globals.LogQueue.Enqueue($"Stopped blocking all traffic for IP: {ip}");
        }
    }

    public static async Task BlockTrafficByPort(int port)
    {
        IntPtr packetBuffer = Marshal.AllocHGlobal(1500); // Allocate buffer for packet

        try
        {
            // Using a filter to block all traffic to and from the specified port
            using (var divert = new WinDivertWrapper($"tcp.SrcPort == {port} or tcp.DstPort == {port}", WindivertLayer.NETWORK, 0, WindivertFlags.RECV_ONLY))
            {
                // Enqueue log message for start of blocking
                Globals.LogQueue.Enqueue($"Blocking all traffic for port: {port}");

                while (true)
                {
                    uint recvLen;
                    if (divert.Recv(packetBuffer, 1500, out recvLen))
                    {
                        // Capture and log all relevant information
                        unsafe
                        {
                            var ipHeader = (WindivertIphdr*)(packetBuffer + sizeof(WindivertEthhdr));
                            var srcIP = new IPAddress(ipHeader->SrcAddr);
                            var dstIP = new IPAddress(ipHeader->DstAddr);

                            var tcpHeader = (WindivertTcphdr*)(packetBuffer + sizeof(WindivertEthhdr) + sizeof(WindivertIphdr));
                            var srcPort = tcpHeader->SrcPort;
                            var dstPort = tcpHeader->DstPort;
                            var seqNum = tcpHeader->SeqNum;
                            var ackNum = tcpHeader->AckNum;
                            var flags = tcpHeader->Flags;
                            var window = tcpHeader->Window;
                            var checksum = tcpHeader->Checksum;
                            var urgPtr = tcpHeader->UrgPtr;

                            // Log the captured information
                            Globals.LogQueue.Enqueue($"Intercepted packet on port {port}. Length: {recvLen}");
                            Globals.LogQueue.Enqueue($"SrcIP: {srcIP}, DstIP: {dstIP}, SrcPort: {srcPort}, DstPort: {dstPort}");
                            Globals.LogQueue.Enqueue($"SeqNum: {seqNum}, AckNum: {ackNum}, Flags: {flags}, Window: {window}, Checksum: {checksum}, UrgPtr: {urgPtr}");
                        }
                    }
                    else
                    {
                        // Enqueue error log message
                        int error = Marshal.GetLastWin32Error();
                        if (error != 0)
                        {
                            Globals.LogQueue.Enqueue($"Failed to receive packet for blocking. Error: {error}");
                        }
                    }

                    // Prevent high CPU usage
                    await Task.Yield();
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(packetBuffer); // Ensure the allocated buffer is freed
            Globals.LogQueue.Enqueue($"Stopped blocking all traffic for port: {port}");
        }
    }


}