/*
 
    Copyright (c) 2010 Jeffrey Dik <s450r1@gmail.com>
    Copyright (c) 2010 Martin Sustrik <sustrik@250bpm.com>
    Copyright (c) 2010 Michael Compton <michael.compton@littleedge.co.uk>
     
    This file is part of clrzmq.
     
    clrzmq is free software; you can redistribute it and/or modify it under
    the terms of the Lesser GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.
     
    clrzmq is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    Lesser GNU General Public License for more details.
     
    You should have received a copy of the Lesser GNU General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.

*/

using System;
using System.Runtime.InteropServices;
using System.Text;

namespace ZMQ_FFI {

    /// <summary>
    /// Low Level ZeroMQ Foreign Function Interface
    /// </summary>
    public static class C {
        [DllImport("libzmq", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr zmq_init(int io_threads);

        [DllImport("libzmq", CallingConvention = CallingConvention.Cdecl)]
        public static extern int zmq_term(IntPtr context);

        [DllImport("libzmq", CallingConvention = CallingConvention.Cdecl)]
        public static extern int zmq_close(IntPtr socket);

        [DllImport("libzmq", CallingConvention = CallingConvention.Cdecl)]
        public static extern int zmq_setsockopt(IntPtr socket, int option,
                                                IntPtr optval, int optvallen);

        [DllImport("libzmq", CallingConvention = CallingConvention.Cdecl)]
        public static extern int zmq_getsockopt(IntPtr socket, int option,
                                                IntPtr optval,
                                                IntPtr optvallen);

        [DllImport("libzmq", CharSet = CharSet.Ansi,
        CallingConvention = CallingConvention.Cdecl)]
        public static extern int zmq_bind(IntPtr socket, string addr);

        [DllImport("libzmq", CharSet = CharSet.Ansi,
        CallingConvention = CallingConvention.Cdecl)]
        public static extern int zmq_connect(IntPtr socket, string addr);

        [DllImport("libzmq", CallingConvention = CallingConvention.Cdecl)]
        public static extern int zmq_recv(IntPtr socket, IntPtr msg, int flags);

        [DllImport("libzmq", CallingConvention = CallingConvention.Cdecl)]
        public static extern int zmq_send(IntPtr socket, IntPtr msg, int flags);

        [DllImport("libzmq", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr zmq_socket(IntPtr context, int type);

        [DllImport("libzmq", CallingConvention = CallingConvention.Cdecl)]
        public static extern int zmq_msg_close(IntPtr msg);

        [DllImport("libzmq", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr zmq_msg_data(IntPtr msg);

        [DllImport("libzmq", CallingConvention = CallingConvention.Cdecl)]
        public static extern int zmq_msg_init(IntPtr msg);

        [DllImport("libzmq", CallingConvention = CallingConvention.Cdecl)]
        public static extern int zmq_msg_init_size(IntPtr msg, int size);

        [DllImport("libzmq", CallingConvention = CallingConvention.Cdecl)]
        public static extern int zmq_msg_size(IntPtr msg);

        [DllImport("libzmq", CallingConvention = CallingConvention.Cdecl)]
        public static extern int zmq_errno();

        [DllImport("libzmq", CharSet = CharSet.Ansi,
        CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr zmq_strerror(int errnum);

        [DllImport("libzmq", CallingConvention = CallingConvention.Cdecl)]
        public static extern int zmq_device(int device, IntPtr inSocket,
                                            IntPtr outSocket);

        [DllImport("libzmq", CallingConvention = CallingConvention.Cdecl)]
        public static extern void zmq_version(IntPtr major, IntPtr minor, IntPtr patch);
    }
}

namespace ZMQ {
    using ZMQ_FFI;

    /// <summary>
    /// Message transport types
    /// </summary>
    public enum Transport {
        INPROC = 1,
        TCP = 2,
        IPC = 3,
        PGM = 4,
        EPGM = 5
    }

    /// <summary>
    /// Socket options
    /// </summary>
    public enum SocketOpt {
        HWM = 1,
        SWAP = 3,
        AFFINITY = 4,
        IDENTITY = 5,
        SUBSCRIBE = 6,
        UNSUBSCRIBE = 7,
        RATE = 8,
        RECOVERY_IVL = 9,
        MCAST_LOOP = 10,
        SNDBUF = 11,
        RCVBUF = 12,
        RCVMORE = 13,
        FD = 14,
        EVENTS = 15,
        TYPE = 16,
        LINGER = 17,
        RECONNECT_IVL = 18,
        BACKLOG = 19
    }

    /// <summary>
    /// Socket types
    /// </summary>
    public enum SocketType {
        PAIR = 0,
        PUB = 1,
        SUB = 2,
        REQ = 3,
        REP = 4,
        XREQ = 5,
        XREP = 6,
        PULL = 7,
        UPSTREAM = 7,       //***OBSOLETE: To be removed in 3.x***
        PUSH = 8,
        DOWNSTREAM = 8      //***OBSOLETE: To be removed in 3.x***
    }

    /// <summary>
    /// Device types
    /// </summary>
    public enum DeviceType {
        STREAMER = 1,
        FORWARDER = 2,
        QUEUE = 3
    }

    /// <summary>
    /// Send and receive options
    /// </summary>
    public enum SendRecvOpt {
        NOBLOCK = 1,
        SNDMORE = 2
    }
    
    /// <summary>
    /// CLRZeroMQ Exception type
    /// </summary>
    public class Exception : System.Exception {
        private int errno;

        /// <summary>
        /// Get ZeroMQ Errno
        /// </summary>
        public int Errno {
            get { return errno; }
        }

        public Exception()
            : base(Marshal.PtrToStringAnsi(C.zmq_strerror(C.zmq_errno()))) {
            this.errno = C.zmq_errno();
        }
    }

    public static class ZMQUtil {
        public static string Version(out int major, out int minor, out int patch) {
            int sizeofInt32 = Marshal.SizeOf(Type.GetType("System.Int32"));
            IntPtr maj = Marshal.AllocHGlobal(sizeofInt32);
            IntPtr min = Marshal.AllocHGlobal(sizeofInt32);
            IntPtr pat = Marshal.AllocHGlobal(sizeofInt32);
            C.zmq_version(maj, min, pat);
            major = Marshal.ReadInt32(maj);
            minor = Marshal.ReadInt32(min);
            patch = Marshal.ReadInt32(pat);
            Marshal.FreeHGlobal(maj);
            Marshal.FreeHGlobal(min);
            Marshal.FreeHGlobal(pat);
            return major.ToString() + "." + minor.ToString() + "." + patch.ToString();
        }
    }

    /// <summary>
    /// ZMQ Context
    /// </summary>
    public class Context : IDisposable {
        private IntPtr ptr;

        /// <summary>
        /// Create ZMQ Context
        /// </summary>
        /// <param name="io_threads">Thread pool size</param>
        public Context(int io_threads) {
            ptr = C.zmq_init(io_threads);
            if (ptr == IntPtr.Zero)
                throw new Exception();
        }

        ~Context() {
            Dispose(false);
        }

        /// <summary>
        /// Creates a new ZMQ socket
        /// </summary>
        /// <param name="type">Type of socket to be created</param>
        /// <returns>A new ZMQ socket</returns>
        public Socket Socket(SocketType type) {
            IntPtr socket_ptr = C.zmq_socket(ptr, (int)type);
            if (ptr == IntPtr.Zero)
                throw new Exception();

            return new Socket(socket_ptr);
        }

        public void Dispose() {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing) {
            if (ptr != IntPtr.Zero) {
                int rc = C.zmq_term(ptr);
                ptr = IntPtr.Zero;
                if (rc != 0)
                    throw new Exception();
            }
        }
    }

    /// <summary>
    /// ZMQ Socket
    /// </summary>
    public class Socket : IDisposable {
        private IntPtr ptr;
        private IntPtr msg;

        //  TODO:  This won't hold on different platforms.
        //  Isn't there a way to access POSIX error codes in CLR?
        private const int EAGAIN = 11;

        //  Figure out size of zmq_msg_t structure.
        //  It's size of pointer + 2 bytes + VSM buffer size.
        private const int ZMQ_MAX_VSM_SIZE = 30;
        private int ZMQ_MSG_T_SIZE = IntPtr.Size + 2 + ZMQ_MAX_VSM_SIZE;

        /// <summary>
        /// This constructor should not be called directly, use the Context 
        /// Socket method
        /// </summary>
        /// <param name="ptr">Pointer to a socket</param>
        public Socket(IntPtr ptr) {
            this.ptr = ptr;
            msg = Marshal.AllocHGlobal(ZMQ_MSG_T_SIZE);
        }

        ~Socket() {
            Dispose(false);
        }

        public void Dispose() {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing) {
            if (msg != IntPtr.Zero) {
                Marshal.FreeHGlobal(msg);
                msg = IntPtr.Zero;
            }

            if (ptr != IntPtr.Zero) {
                int rc = C.zmq_close(ptr);
                ptr = IntPtr.Zero;
                if (rc != 0)
                    throw new Exception();
            }
        }

        /// <summary>
        /// Set Socket Option
        /// </summary>
        /// <param name="option">Socket Option</param>
        /// <param name="value">Option value</param>
        /// <exception cref="ZMQ.Exception">ZMQ Exception</exception>
        public void SetSockOpt(SocketOpt option, string value) {
            IntPtr valPtr = Marshal.StringToHGlobalAnsi(value);
            if (C.zmq_setsockopt(ptr, (int)option, valPtr, value.Length) != 0)
                throw new Exception();
            Marshal.FreeHGlobal(valPtr);
        }

        /// <summary>
        /// Set Socket Option
        /// </summary>
        /// <param name="option">Socket Option</param>
        /// <param name="value">Option value</param>
        /// <exception cref="ZMQ.Exception">ZMQ Exception</exception>
        public void SetSockOpt(SocketOpt option, ulong value) {
            int sizeOfValue = Marshal.SizeOf(value.GetType());
            IntPtr valPtr = Marshal.AllocHGlobal(sizeOfValue);
            Marshal.WriteInt64(valPtr, unchecked((long)value));
            if (C.zmq_setsockopt(ptr, (int)option, valPtr, sizeOfValue) != 0)
                throw new Exception();
            Marshal.FreeHGlobal(valPtr);
        }

        /// <summary>
        /// Set Socket Option
        /// </summary>
        /// <param name="option">Socket Option</param>
        /// <param name="value">Option value</param>
        /// <exception cref="ZMQ.Exception">ZMQ Exception</exception>
        public void SetSockOpt(SocketOpt option, byte[] value) {
            int sizeOfValue = Marshal.SizeOf(value.Length);
            IntPtr valPtr = Marshal.AllocHGlobal(sizeOfValue);
            Marshal.WriteInt64(valPtr, sizeOfValue);
            Marshal.Copy(value, 0, valPtr, sizeOfValue);
            if (C.zmq_setsockopt(ptr, (int)option, valPtr, sizeOfValue) != 0)
                throw new Exception();
            Marshal.FreeHGlobal(valPtr);
        }

        /// <summary>
        /// Set Socket Option
        /// </summary>
        /// <param name="option">Socket Option</param>
        /// <param name="value">Option value</param>
        /// <exception cref="ZMQ.Exception">ZMQ Exception</exception>
        public void SetSockOpt(SocketOpt option, long value) {
            int sizeOfValue = Marshal.SizeOf(value.GetType());
            IntPtr valPtr = Marshal.AllocHGlobal(sizeOfValue);
            Marshal.WriteInt64(valPtr, value);
            if (C.zmq_setsockopt(ptr, (int)option, valPtr, sizeOfValue) != 0)
                throw new Exception();
            Marshal.FreeHGlobal(valPtr);
        }

        /// <summary>
        /// Get the socket option value
        /// </summary>
        /// <param name="option">Socket Option</param>
        /// <returns>Option value</returns>
        /// <exception cref="ZMQ.Exception">ZMQ Exception</exception>
        public object GetSockOpt(SocketOpt option) {
            int sizeOfInt64 = Marshal.SizeOf(Type.GetType("System.Int64"));
            object output;
            IntPtr val;
            IntPtr len;
            if (option == SocketOpt.IDENTITY) {                
                val = Marshal.AllocHGlobal(255);
                len = Marshal.AllocHGlobal(sizeOfInt64);
                Marshal.WriteInt64(len, 255);
                if (C.zmq_getsockopt(ptr, (int)option, val, len) != 0)
                    throw new Exception();
                output = Marshal.PtrToStringAnsi(val,
                                                 (int)Marshal.ReadInt64(len));
            } else {
                val = Marshal.AllocHGlobal(sizeOfInt64);
                len = Marshal.AllocHGlobal(sizeOfInt64);
                Marshal.WriteInt64(len, sizeOfInt64);
                if (C.zmq_getsockopt(ptr, (int)option, val, len) != 0)
                    throw new Exception();
                //Unchecked casting of uint64 options
                if (option == SocketOpt.HWM || option == SocketOpt.AFFINITY ||
                    option == SocketOpt.SNDBUF || option == SocketOpt.RCVBUF) {
                    output = unchecked((ulong)Marshal.ReadInt64(val));
                } else {
                    output = Marshal.ReadInt64(val);
                }
            }
            Marshal.FreeHGlobal(val);
            Marshal.FreeHGlobal(len);
            return output;
        }

        /// <summary>
        /// Bind the socket to address
        /// </summary>
        /// <param name="addr">Socket Address</param>
        /// <exception cref="ZMQ.Exception">ZMQ Exception</exception>
        public void Bind(string addr) {
            if (C.zmq_bind(ptr, addr) != 0)
                throw new Exception();
        }
        
        /// <summary>
        /// Bind the socket to address
        /// </summary>
        /// <param name="transport">Socket transport type</param>
        /// <param name="addr">Socket address</param>
        /// <param name="port">Socket port</param>
        /// <exception cref="ZMQ.Exception">ZMQ Exception</exception>
        public void Bind(Transport transport, string addr, uint port) {
            Bind(Enum.GetName(typeof(Transport), transport).ToLower() + "://" + addr + ":" + port);
        }

        /// <summary>
        /// Bind the socket to address
        /// </summary>
        /// <param name="transport">Socket transport type</param>
        /// <param name="addr">Socket address</param>
        /// <exception cref="ZMQ.Exception">ZMQ Exception</exception>
        public void Bind(Transport transport, string addr) {
            Bind(Enum.GetName(typeof(Transport), transport).ToLower() + "://" + addr);
        }

        /// <summary>
        /// Connect socket to destination address
        /// </summary>
        /// <param name="addr">Destination Address</param>
        /// <exception cref="ZMQ.Exception">ZMQ Exception</exception>
        public void Connect(string addr) {
            if (C.zmq_connect(ptr, addr) != 0)
                throw new Exception();
        }

        /// <summary>
        /// Listen for message
        /// </summary>
        /// <returns>Message</returns>
        /// <exception cref="ZMQ.Exception">ZMQ Exception</exception>
        public byte[] Recv() {
            return Recv(0);
        }

        /// <summary>
        /// Listen for message
        /// </summary>
        /// <param name="flags">Receive Option</param>
        /// <returns>Message</returns>
        /// <exception cref="ZMQ.Exception">ZMQ Exception</exception>
        public byte[] Recv(int flags) {
            byte[] message;
            if (C.zmq_msg_init(msg) != 0)
                throw new Exception();
            if (C.zmq_recv(ptr, msg, flags) != 0)
                throw new Exception();
            message = new byte[C.zmq_msg_size(msg)];
            Marshal.Copy(C.zmq_msg_data(msg), message, 0, message.Length);
            C.zmq_msg_close(msg);
            return message;
        }

        /// <summary>
        /// Send Message
        /// </summary>
        /// <param name="message">Message</param>
        /// <exception cref="ZMQ.Exception">ZMQ Exception</exception>
        public void Send(byte[] message) {
            Send(message, 0);
        }

        /// <summary>
        /// Send Message
        /// </summary>
        /// <param name="message">Message</param>
        /// <param name="flags">Send Options</param>
        /// <exception cref="ZMQ.Exception">ZMQ Exception</exception>
        public void Send(byte[] message, int flags) {
            if (C.zmq_msg_init_size(msg, message.Length) != 0)
                throw new Exception();
            Marshal.Copy(message, 0, C.zmq_msg_data(msg), message.Length);
            if (C.zmq_send(ptr, msg, flags) != 0)
                throw new Exception();
        }

        public void Send(string message) {
            Send(message, 0);
        }

        public void Send(string message, int flags) {
            Send(Encoding.ASCII.GetBytes(message), flags);
        }

        /// <summary>
        /// Gets or Sets socket identity 
        /// </summary>
        /// <exception cref="ZMQ.Exception">ZMQ Exception</exception>
        public string Identity {
            get {
                return (string)GetSockOpt(SocketOpt.IDENTITY);
            }
            set {
                SetSockOpt(SocketOpt.IDENTITY, value);
            }
        }

        /// <summary>
        /// Gets or Sets socket High Water Mark
        /// </summary>
        /// <exception cref="ZMQ.Exception">ZMQ Exception</exception>
        public ulong HWM {
            get {
                return (ulong)GetSockOpt(SocketOpt.HWM);
            }
            set {
                SetSockOpt(SocketOpt.HWM, value);
            }
        }

        /// <summary>
        /// Gets socket more messages indicator (multipart message)
        /// </summary>
        /// <exception cref="ZMQ.Exception">ZMQ Exception</exception>
        public bool RcvMore {
            get {
                return (long)GetSockOpt(SocketOpt.RCVMORE) == 1;
            }
        }

        /// <summary>
        /// Gets or Sets socket swap
        /// </summary>
        /// <exception cref="ZMQ.Exception">ZMQ Exception</exception>
        public long Swap {
            get {
                return (long)GetSockOpt(SocketOpt.SWAP);
            }
            set {
                SetSockOpt(SocketOpt.SWAP, value);
            }
        }

        /// <summary>
        /// Gets or Sets socket thread affinity 
        /// </summary>
        /// <exception cref="ZMQ.Exception">ZMQ Exception</exception>
        public ulong Affinity {
            get {
                return (ulong)GetSockOpt(SocketOpt.AFFINITY);
            }
            set {
                SetSockOpt(SocketOpt.AFFINITY, value);
            }
        }

        /// <summary>
        /// Gets or Sets socket transfer rate 
        /// </summary>
        /// <exception cref="ZMQ.Exception">ZMQ Exception</exception>
        public long Rate {
            get {
                return (long)GetSockOpt(SocketOpt.RATE);
            }
            set {
                SetSockOpt(SocketOpt.RATE, value);
            }
        }

        /// <summary>
        /// Gets or Sets socket recovery interval 
        /// </summary>
        /// <exception cref="ZMQ.Exception">ZMQ Exception</exception>
        public long RecoveryIvl {
            get {
                return (long)GetSockOpt(SocketOpt.RECOVERY_IVL);
            }
            set {
                SetSockOpt(SocketOpt.RECOVERY_IVL, value);
            }
        }

        /// <summary>
        /// Gets or Sets socket MultiCast Loop 
        /// </summary>
        /// <exception cref="ZMQ.Exception">ZMQ Exception</exception>
        public long MCastLoop {
            get {
                return (long)GetSockOpt(SocketOpt.MCAST_LOOP);
            }
            set {
                SetSockOpt(SocketOpt.MCAST_LOOP, value);
            }
        }

        /// <summary>
        /// Gets or Sets socket Send buffer size(bytes) 
        /// </summary>
        /// <exception cref="ZMQ.Exception">ZMQ Exception</exception>
        public ulong SndBuf {
            get {
                return (ulong)GetSockOpt(SocketOpt.SNDBUF);
            }
            set {
                SetSockOpt(SocketOpt.SNDBUF, value);
            }
        }

        /// <summary>
        /// Gets or Sets socket Receive buffer size(bytes) 
        /// </summary>
        /// <exception cref="ZMQ.Exception">ZMQ Exception</exception>
        public ulong RcvBuf {
            get {
                return (ulong)GetSockOpt(SocketOpt.RCVBUF);
            }
            set {
                SetSockOpt(SocketOpt.RCVBUF, value);
            }
        }

        /// <summary>
        /// Set socket subscription filter
        /// </summary>
        /// <param name="filter">Filter</param>
        /// <exception cref="ZMQ.Exception">ZMQ Exception</exception>
        public void Subscribe(byte[] filter) {
            SetSockOpt(SocketOpt.SUBSCRIBE, filter);
        }

        /// <summary>
        /// Set socket subscription filter
        /// </summary>
        /// <param name="filter">Filter</param>
        /// <exception cref="ZMQ.Exception">ZMQ Exception</exception>
        public void Subscribe(string filter) {
            SetSockOpt(SocketOpt.SUBSCRIBE, filter);
        }

        /// <summary>
        /// Remove socket subscription filter
        /// </summary>
        /// <param name="filter">Filter</param>
        /// <exception cref="ZMQ.Exception">ZMQ Exception</exception>
        public void Unsubscribe(byte[] filter) {
            SetSockOpt(SocketOpt.UNSUBSCRIBE, filter);
        }

        /// <summary>
        /// Remove socket subscription filter
        /// </summary>
        /// <param name="filter">Filter</param>
        /// <exception cref="ZMQ.Exception">ZMQ Exception</exception>
        public void Unsubscribe(string filter) {
            SetSockOpt(SocketOpt.UNSUBSCRIBE, filter);
        }

        /// <summary>
        /// ZMQ Device creation
        /// </summary>
        public static class Device {
            /// <summary>
            /// Create ZMQ Device
            /// </summary>
            /// <param name="device">Device type</param>
            /// <param name="inSocket">Input socket</param>
            /// <param name="outSocket">Output socket</param>
            /// <exception cref="ZMQ.Exception">ZMQ Exception</exception>
            public static void Create(DeviceType device, Socket inSocket,
                                      Socket outSocket) {
                if (C.zmq_device((int)device, inSocket.ptr, outSocket.ptr) != 0)
                    throw new Exception();
            }

            /// <summary>
            /// Create ZMQ Queue Device
            /// </summary>
            /// <param name="inSocket">Input socket</param>
            /// <param name="outSocket">Output socket</param>
            /// <exception cref="ZMQ.Exception">ZMQ Exception</exception>
            public static void Queue(Socket inSocket, Socket outSocket) {
                Create(DeviceType.QUEUE, inSocket, outSocket);
            }

            /// <summary>
            /// Create ZMQ Forwarder Device
            /// </summary>
            /// <param name="inSocket">Input socket</param>
            /// <param name="outSocket">Output socket</param>
            /// <exception cref="ZMQ.Exception">ZMQ Exception</exception>
            public static void Forwarder(Socket inSocket, Socket outSocket) {
                Create(DeviceType.FORWARDER, inSocket, outSocket);
            }

            /// <summary>
            /// Create ZMQ Streamer Device
            /// </summary>
            /// <param name="inSocket">Input socket</param>
            /// <param name="outSocket">Output socket</param>
            /// <exception cref="ZMQ.Exception">ZMQ Exception</exception>
            public static void Streamer(Socket inSocket, Socket outSocket) {
                Create(DeviceType.STREAMER, inSocket, outSocket);
            }
        }
    }
}