public class PacketFilter
{
    // Enum for predefined filters
    public enum FilterType
    {
        True,
        Ip,
        Tcp
    }

    // Method to get predefined filters
    public static string GetFilter(FilterType filterType)
    {
        switch (filterType)
        {
            case FilterType.True:
                return "true";
            case FilterType.Ip:
                return "ip";
            case FilterType.Tcp:
                return "tcp";
            default:
                throw new ArgumentException("Invalid filter type");
        }
    }

    // Method to create a filter for specific port
    public static string CreatePortFilter(int port, bool isSourcePort = true)
    {
        if (isSourcePort)
        {
            return $"tcp.SrcPort == {port}";
        }
        else
        {
            return $"tcp.DstPort == {port}";
        }
    }

    // Method to create a filter for specific source IP
    public static string CreateSourceIPFilter(string ip)
    {
        return $"ip.SrcAddr == {ip}";
    }

    // Method to create a filter for specific destination IP
    public static string CreateDestinationIPFilter(string ip)
    {
        return $"ip.DstAddr == {ip}";
    }

    // Scenario: Allow a specific source IP to go to a specific destination from a specific source port
    public static string AllowSourceIPToDestinationFromPort(string sourceIP, string destinationIP, int port)
    {
        return $"ip.SrcAddr == {sourceIP} and ip.DstAddr == {destinationIP} and tcp.SrcPort == {port}";
    }

    // Scenario: Block all traffic except from a specific source IP
    public static string BlockAllExceptSourceIP(string sourceIP)
    {
        return $"not ip.SrcAddr == {sourceIP}";
    }

    // Scenario: Allow only traffic to a specific destination IP
    public static string AllowOnlyToDestinationIP(string destinationIP)
    {
        return $"ip.DstAddr == {destinationIP}";
    }

    // Scenario: Block traffic to a specific destination port
    public static string BlockTrafficToPort(int port)
    {
        return $"not tcp.DstPort == {port}";
    }

    // Scenario: Allow specific protocol traffic (e.g., UDP, ICMP)
    public static string AllowSpecificProtocol(string protocol)
    {
        return $"{protocol}";
    }

    // Scenario: Block traffic from a specific range of IP addresses
    public static string BlockTrafficFromIPRange(string ipRange)
    {
        return $"not ip.SrcAddr == {ipRange}";
    }

    // Scenario: Allow only secure traffic (e.g., HTTPS on port 443)
    public static string AllowOnlySecureTraffic()
    {
        return $"tcp.DstPort == 443";
    }

    // Method to create a custom filter
    public static string CreateCustomFilter(string filterExpression)
    {
        return filterExpression;
    }
}
