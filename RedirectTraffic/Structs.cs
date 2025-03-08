using System;
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential)]
public unsafe struct WindivertEthhdr
{
    public fixed byte DstAddr[6];
    public fixed byte SrcAddr[6];
    public ushort EthType;
}

[StructLayout(LayoutKind.Sequential)]
public struct WindivertAddress
{
    public long Timestamp;
    public uint Layer;
    public uint Event;
    public uint Sniffed;
    public uint Outbound;
    public uint Loopback;
    public uint Impostor;
    public uint IPv6;
    public uint IPChecksum;
    public uint TCPChecksum;
    public uint UDPChecksum;
    public uint Reserved1;
    public uint Reserved2;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] NetworkData;
}

[StructLayout(LayoutKind.Sequential)]
public unsafe struct WindivertIphdr
{
    public byte VersionAndHdrLength;
    public byte TOS;
    public ushort Length;
    public ushort Id;
    public ushort FragOff0;
    public byte TTL;
    public byte Protocol;
    public ushort Checksum;
    public uint SrcAddr;
    public uint DstAddr;

    public byte Version
    {
        get => (byte)(VersionAndHdrLength >> 4);
        set => VersionAndHdrLength = (byte)((VersionAndHdrLength & 0x0F) | (value << 4));
    }

    public byte HdrLength
    {
        get => (byte)(VersionAndHdrLength & 0x0F);
        set => VersionAndHdrLength = (byte)((VersionAndHdrLength & 0xF0) | (value & 0x0F));
    }
}

[StructLayout(LayoutKind.Sequential)]
public unsafe struct WindivertIpv6hdr
{
    public byte TrafficClass0AndVersion;
    public byte FlowLabel0AndTrafficClass1;
    public ushort FlowLabel1;
    public ushort Length;
    public byte NextHdr;
    public byte HopLimit;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
    public uint[] SrcAddr;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
    public uint[] DstAddr;
}

[StructLayout(LayoutKind.Sequential)]
public unsafe struct WindivertIcmphdr
{
    public byte Type;
    public byte Code;
    public ushort Checksum;
    public uint Body;
}

[StructLayout(LayoutKind.Sequential)]
public unsafe struct WindivertIcmpv6hdr
{
    public byte Type;
    public byte Code;
    public ushort Checksum;
    public uint Body;
}

[StructLayout(LayoutKind.Sequential)]
public unsafe struct WindivertTcphdr
{
    public ushort SrcPort;
    public ushort DstPort;
    public uint SeqNum;
    public uint AckNum;
    public byte DataOffsetAndReserved;
    public byte Flags;
    public ushort Window;
    public ushort Checksum;
    public ushort UrgPtr;

    public bool Syn => (Flags & 0x02) != 0;
    public bool Ack => (Flags & 0x10) != 0;

    public byte DataOffset
    {
        get => (byte)(DataOffsetAndReserved >> 4);
        set => DataOffsetAndReserved = (byte)((DataOffsetAndReserved & 0x0F) | (value << 4));
    }
}

[StructLayout(LayoutKind.Sequential)]
public unsafe struct WindivertUdphdr
{
    public ushort SrcPort;
    public ushort DstPort;
    public ushort Length;
    public ushort Checksum;
}
