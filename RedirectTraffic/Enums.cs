using System;

public enum WindivertLayer
{
    NETWORK = 0,
    NETWORK_FORWARD = 1,
    FLOW = 2,
    SOCKET = 3,
    REFLECT = 4
}

[Flags]
public enum WindivertFlags : ulong
{
    SNIFF = 0x0001,
    DROP = 0x0002,
    RECV_ONLY = 0x0004,
    READ_ONLY = RECV_ONLY,
    SEND_ONLY = 0x0008,
    WRITE_ONLY = SEND_ONLY,
    NO_INSTALL = 0x0010,
    FRAGMENTS = 0x0020
}

public enum WindivertEvent
{
    NETWORK_PACKET = 0,
    FLOW_ESTABLISHED = 1,
    FLOW_DELETED = 2,
    SOCKET_BIND = 3,
    SOCKET_CONNECT = 4,
    SOCKET_LISTEN = 5,
    SOCKET_ACCEPT = 6,
    SOCKET_CLOSE = 7,
    REFLECT_OPEN = 8,
    REFLECT_CLOSE = 9
}

public enum WindivertParam
{
    QUEUE_LENGTH = 0,
    QUEUE_TIME = 1,
    QUEUE_SIZE = 2,
    VERSION_MAJOR = 3,
    VERSION_MINOR = 4
}

public enum WindivertShutdown
{
    RECV = 0x1,
    SEND = 0x2,
    BOTH = 0x3
}
