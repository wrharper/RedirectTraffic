using System;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

public class WinDivertWrapper : IDisposable
{
    private const string DllName = "WindivertWrapper.dll";
    private IntPtr handle;

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "OpenEx")]
    private static extern IntPtr OpenEx(string filter, int layer, short priority, ulong flags);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "CloseEx")]
    private static extern bool CloseEx();

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "RecvExx")]
    private static extern bool RecvExx(IntPtr address, IntPtr packet, uint packetLen, out uint recvLen);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "RecvExEx")]
    private static extern bool RecvExEx(IntPtr address, IntPtr packet, uint packetLen, out uint recvLen, ulong flags, out uint addrLen, IntPtr lpOverlapped);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SendExx")]
    private static extern bool SendExx(IntPtr address, IntPtr packet, uint packetLen, out uint sendLen);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SendExEx")]
    private static extern bool SendExEx(IntPtr address, IntPtr packet, uint packetLen, out uint sendLen, ulong flags, uint addrLen, IntPtr lpOverlapped);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "ShutdownEx")]
    private static extern bool ShutdownEx(int how);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "SetParamEx")]
    private static extern bool SetParamEx(int param, ulong value);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "GetParamEx")]
    private static extern bool GetParamEx(int param, out ulong value);

    public WinDivertWrapper(string filter, WindivertLayer layer, short priority, WindivertFlags flags)
    {
        handle = OpenEx(filter, (int)layer, priority, (ulong)flags);
        if (handle == IntPtr.Zero)
        {
            throw new InvalidOperationException("Failed to open WinDivert handle.");
        }
    }

    public void Close()
    {
        if (handle != IntPtr.Zero)
        {
            CloseEx();
            handle = IntPtr.Zero;
        }
    }

    public bool Recv(IntPtr pPacket, uint packetLen, out uint pRecvLen)
    {
        return RecvExx(IntPtr.Zero, pPacket, packetLen, out pRecvLen);
    }

    public bool RecvEx(IntPtr pPacket, uint packetLen, out uint pRecvLen, WindivertFlags flags, out uint pAddrLen, IntPtr lpOverlapped)
    {
        return RecvExEx(IntPtr.Zero, pPacket, packetLen, out pRecvLen, (ulong)flags, out pAddrLen, lpOverlapped);
    }

    public bool Send(IntPtr pPacket, uint packetLen, out uint pSendLen)
    {
        return SendExx(IntPtr.Zero, pPacket, packetLen, out pSendLen);
    }

    public bool SendEx(IntPtr pPacket, uint packetLen, out uint pSendLen, WindivertFlags flags, uint addrLen, IntPtr lpOverlapped)
    {
        return SendExEx(IntPtr.Zero, pPacket, packetLen, out pSendLen, (ulong)flags, addrLen, lpOverlapped);
    }

    public bool Shutdown(WindivertShutdown how)
    {
        return ShutdownEx((int)how);
    }

    public bool SetParam(WindivertParam param, ulong value)
    {
        return SetParamEx((int)param, value);
    }

    public bool GetParam(WindivertParam param, out ulong pValue)
    {
        return GetParamEx((int)param, out pValue);
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
