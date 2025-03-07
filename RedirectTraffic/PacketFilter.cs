using System;

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

    // Method to create a custom filter
    public static string CreateCustomFilter(string filterExpression)
    {
        return filterExpression;
    }
}
