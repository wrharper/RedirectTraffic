using System;
using System.Runtime.InteropServices;

public class WinDivertWrapper : IDisposable
{
    private const string DLL_NAME = "WindivertWrapper.dll";
    private IntPtr handle;

    [DllImport(DLL_NAME, CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Ansi)]
    private static extern IntPtr WindivertOpen(string filter, int layer, short priority, ulong flags);

    [DllImport(DLL_NAME, CallingConvention = CallingConvention.Winapi)]
    private static extern bool WindivertClose(IntPtr handle);

    [DllImport(DLL_NAME, CallingConvention = CallingConvention.Winapi)]
    private static extern bool WindivertRecv(IntPtr handle, IntPtr pPacket, uint packetLen, out uint pRecvLen, out WindivertAddress pAddr);

    [DllImport(DLL_NAME, CallingConvention = CallingConvention.Winapi)]
    private static extern bool WindivertRecvEx(IntPtr handle, IntPtr pPacket, uint packetLen, out uint pRecvLen, ulong flags, out WindivertAddress pAddr, out uint pAddrLen, IntPtr lpOverlapped);

    [DllImport(DLL_NAME, CallingConvention = CallingConvention.Winapi)]
    private static extern bool WindivertSend(IntPtr handle, IntPtr pPacket, uint packetLen, out uint pSendLen, ref WindivertAddress pAddr);

    [DllImport(DLL_NAME, CallingConvention = CallingConvention.Winapi)]
    private static extern bool WindivertSendEx(IntPtr handle, IntPtr pPacket, uint packetLen, out uint pSendLen, ulong flags, ref WindivertAddress pAddr, uint addrLen, IntPtr lpOverlapped);

    [DllImport(DLL_NAME, CallingConvention = CallingConvention.Winapi)]
    private static extern bool WindivertShutdown(IntPtr handle, int how);

    [DllImport(DLL_NAME, CallingConvention = CallingConvention.Winapi)]
    private static extern bool WindivertSetParam(IntPtr handle, int param, ulong value);

    [DllImport(DLL_NAME, CallingConvention = CallingConvention.Winapi)]
    private static extern bool WindivertGetParam(IntPtr handle, int param, out ulong pValue);

    [DllImport(DLL_NAME, CallingConvention = CallingConvention.Winapi)]
    private static extern bool WindivertHelperCalcChecksums(IntPtr pPacket, uint packetLen, ref WindivertAddress pAddr, ulong flags);

    public WinDivertWrapper(string filter, WindivertLayer layer, short priority, WindivertFlags flags)
    {
        handle = WindivertOpen(filter, (int)layer, priority, (ulong)flags);
        if (handle == IntPtr.Zero)
        {
            throw new InvalidOperationException("Failed to open WinDivert handle.");
        }
    }

    public void Close()
    {
        if (handle != IntPtr.Zero)
        {
            WindivertClose(handle);
            handle = IntPtr.Zero;
        }
    }

    public bool Recv(IntPtr pPacket, uint packetLen, out uint pRecvLen, out WindivertAddress pAddr)
    {
        return WindivertRecv(handle, pPacket, packetLen, out pRecvLen, out pAddr);
    }

    public bool RecvEx(IntPtr pPacket, uint packetLen, out uint pRecvLen, WindivertFlags flags, out WindivertAddress pAddr, out uint pAddrLen, IntPtr lpOverlapped)
    {
        return WindivertRecvEx(handle, pPacket, packetLen, out pRecvLen, (ulong)flags, out pAddr, out pAddrLen, lpOverlapped);
    }

    public bool Send(IntPtr pPacket, uint packetLen, out uint pSendLen, ref WindivertAddress pAddr)
    {
        return WindivertSend(handle, pPacket, packetLen, out pSendLen, ref pAddr);
    }

    public bool SendEx(IntPtr pPacket, uint packetLen, out uint pSendLen, WindivertFlags flags, ref WindivertAddress pAddr, uint addrLen, IntPtr lpOverlapped)
    {
        return WindivertSendEx(handle, pPacket, packetLen, out pSendLen, (ulong)flags, ref pAddr, addrLen, lpOverlapped);
    }

    public bool Shutdown(WindivertShutdown how)
    {
        return WindivertShutdown(handle, (int)how);
    }

    public bool SetParam(WindivertParam param, ulong value)
    {
        return WindivertSetParam(handle, (int)param, value);
    }

    public bool GetParam(WindivertParam param, out ulong pValue)
    {
        return WindivertGetParam(handle, (int)param, out pValue);
    }

    public static bool CalcChecksums(IntPtr pPacket, uint packetLen, ref WindivertAddress pAddr, ulong flags)
    {
        return WindivertHelperCalcChecksums(pPacket, packetLen, ref pAddr, flags);
    }

    public void Dispose()
    {
        Close();
        GC.SuppressFinalize(this);
    }

    ~WinDivertWrapper()
    {
        Close();
    }
}
