/*
 
    Copyright (c) 2010 Jeffrey Dik <s450r1@gmail.com>
    Copyright (c) 2010 Martin Sustrik <sustrik@250bpm.com>
     
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

public class ZMQ
{
    internal class C
    {
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

        [DllImport("libzmq", CharSet = CharSet.Ansi, CallingConvention = 
                   CallingConvention.Cdecl)]
        public static extern int zmq_bind(IntPtr socket, string addr);

        [DllImport("libzmq", CharSet = CharSet.Ansi, CallingConvention = 
                   CallingConvention.Cdecl)]
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

        [DllImport("libzmq", CharSet = CharSet.Ansi, CallingConvention = 
                   CallingConvention.Cdecl)]
        public static extern IntPtr zmq_strerror(int errnum);

        [DllImport("libzmq", CallingConvention = CallingConvention.Cdecl)]
        public static extern int zmq_device(int device, IntPtr inSocket, 
                                            IntPtr outSocket);
    }

    public const int HWM = 1;
    public const int SWAP = 3;
    public const int AFFINITY = 4;
    public const int IDENTITY = 5;
    public const int SUBSCRIBE = 6;
    public const int UNSUBSCRIBE = 7;
    public const int RATE = 8;
    public const int RECOVERY_IVL = 9;
    public const int MCAST_LOOP = 10;
    public const int SNDBUF = 11;
    public const int RCVBUF = 12;
    public const int RCVMORE = 13;
    public const int FD = 14;
    public const int EVENTS = 15;
    public const int TYPE = 16;
    public const int LINGER = 17;
    public const int RECONNECT_IVL = 18;
    public const int BACKLOG = 19;

    public const int PAIR = 0;
    public const int PUB = 1;
    public const int SUB = 2;
    public const int REQ = 3;
    public const int REP = 4;
    public const int XREQ = 5;
    public const int XREP = 6;
    public const int PULL = 7;
    public const int PUSH = 8;

    public const int STREAMER = 1;
    public const int FORWARDER = 2;
    public const int QUEUE = 3;

    //  Obsolete.
    public const int UPSTREAM = 7;
    public const int DOWNSTREAM = 8;

    public const int NOBLOCK = 1;

    public static int Device(int device, Socket inSocket, Socket outSocket)
    {
        return C.zmq_device(device, inSocket.Ptr, outSocket.Ptr);
    }

    public class Exception : System.Exception
    {
        private int errno;

        public int Errno {
            get { return errno; }
        }

        public Exception() 
            : base(Marshal.PtrToStringAnsi(C.zmq_strerror(C.zmq_errno())))
        {
            this.errno = C.zmq_errno();
        }
    }

    public class Context : IDisposable
    {
        private IntPtr ptr;

        public Context(int io_threads)
        {
            ptr = C.zmq_init(io_threads);
            if (ptr == IntPtr.Zero)
                throw new Exception();
        }

        ~Context()
        {
            Dispose(false);
        }

        public Socket Socket(int type)
        {
            IntPtr socket_ptr = C.zmq_socket(ptr, type);
            if (ptr == IntPtr.Zero)
                throw new Exception();
            
            return new Socket(socket_ptr);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (ptr != IntPtr.Zero) {
                int rc = C.zmq_term(ptr);
                ptr = IntPtr.Zero;
                if (rc != 0)
                    throw new Exception();
            }
        }
    }

    public class Socket : IDisposable
    {
        private IntPtr ptr;
        private IntPtr msg;

        //  TODO:  This won't hold on different platforms.
        //  Isn't there a way to access POSIX error codes in CLR?
        private const int EAGAIN = 11;

        //  Figure out size of zmq_msg_t structure.
        //  It's size of pointer + 2 bytes + VSM buffer size.
        private const int ZMQ_MAX_VSM_SIZE = 30;
        private int ZMQ_MSG_T_SIZE = IntPtr.Size + 2 + ZMQ_MAX_VSM_SIZE;

        //  Don't call this, call Context.CreateSocket
        public Socket(IntPtr ptr)
        {
            this.ptr = ptr;
            msg = Marshal.AllocHGlobal(ZMQ_MSG_T_SIZE);
        }

        ~Socket()
        {
            Dispose(false);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
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

        public IntPtr Ptr {
            get { return ptr; }
        }

        public void SetSockOpt(int option, string value)
        {
            IntPtr valPtr = Marshal.StringToHGlobalAnsi(value);
            if (C.zmq_setsockopt(ptr, option, valPtr, value.Length) != 0)
                throw new Exception();
            Marshal.FreeHGlobal(valPtr);
        }

        public void SetSockOpt(int option, UInt64 value)
        {
            int sizeOfValue = Marshal.SizeOf(value.GetType());
            IntPtr valPtr = Marshal.AllocHGlobal(sizeOfValue);
            Marshal.WriteInt64(valPtr, unchecked((long)value));
            if (C.zmq_setsockopt(ptr, option, valPtr, sizeOfValue) != 0)
                throw new Exception();
            Marshal.FreeHGlobal(valPtr);
        }

        public void SetSockOpt(int option, Int64 value)
        {
            int sizeOfValue = Marshal.SizeOf(value.GetType());
            IntPtr valPtr = Marshal.AllocHGlobal(sizeOfValue);
            Marshal.WriteInt64(valPtr, (long)value);
            if (C.zmq_setsockopt(ptr, option, valPtr, sizeOfValue) != 0)
                throw new Exception();
            Marshal.FreeHGlobal(valPtr);
        }

        public object GetSockOpt(int option)
        {
            Int64 prototype = 0;
            int sizeOfInt64 = Marshal.SizeOf(prototype.GetType());
            object output;
            IntPtr optVal;
            IntPtr optValLen;
            if (option == IDENTITY) {
                optVal = Marshal.AllocHGlobal(Marshal.SizeOf(255));
                optValLen = Marshal.AllocHGlobal(sizeOfInt64);
                if (C.zmq_getsockopt(ptr, option, optVal, optValLen) != 0) {
                    throw new Exception();
                }
                output = Marshal.PtrToStringAnsi(optVal);
            } else {
                optVal = Marshal.AllocHGlobal(sizeOfInt64);
                optValLen = Marshal.AllocHGlobal(sizeOfInt64);
                if (C.zmq_getsockopt(ptr, option, optVal, optValLen) != 0) {
                    throw new Exception();
                }
                if (option == HWM || option == AFFINITY || option == SNDBUF 
                    || option == RCVBUF) {
                    output = unchecked((ulong)Marshal.ReadInt64(optVal));
                } else {
                    output = Marshal.ReadInt64(optVal);
                }
            }
            Marshal.FreeHGlobal(optVal);
            Marshal.FreeHGlobal(optValLen);
            return output;
        }

        public void Bind(string addr)
        {
            if (C.zmq_bind(ptr, addr) != 0)
                throw new Exception();
        }

        public void Connect(string addr)
        {
            if (C.zmq_connect(ptr, addr) != 0)
                throw new Exception();
        }

        public bool Recv(out byte[] message)
        {
            return Recv(out message, 0);
        }

        public bool Recv(out byte[] message, int flags)
        {
            if (C.zmq_msg_init(msg) != 0)
                throw new Exception();
            int rc = C.zmq_recv(ptr, msg, flags);
            if (rc == 0) {
                message = new byte[C.zmq_msg_size(msg)];
                Marshal.Copy(C.zmq_msg_data(msg), message, 0, message.Length);
                C.zmq_msg_close(msg);
                return true;
            }
            if (C.zmq_errno() == EAGAIN) {
                message = new byte[0];
                return false;
            }
            throw new Exception();
        }

        public bool Send(byte[] message)
        {
            return Send(message, 0);
        }

        public bool Send(byte[] message, int flags)
        {
            if (C.zmq_msg_init_size(msg, message.Length) != 0)
                throw new Exception();
            Marshal.Copy(message, 0, C.zmq_msg_data(msg), message.Length);
            int rc = C.zmq_send(ptr, msg, flags);
            //  No need for zmq_msg_close here as the message is empty anyway.
            if (rc == 0)
                return true;
            if (C.zmq_errno() == EAGAIN)
                return false;
            throw new Exception();
        }
    }
}
