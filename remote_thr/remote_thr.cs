﻿
using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using System.Diagnostics;
using ZMQ;

class remote_thr
{

    static unsafe int Main(string[] args)
    {
        if (args.Length != 3)
        {
            Console.Out.WriteLine("usage: remote_thr <address> " +
                "<message-size> <message-count>\n");
            return 1;
        }

        String address = args[0];
        uint messageSize = Convert.ToUInt32(args[1]);
        int messageCount = Convert.ToInt32(args[2]);

        //  Initialise 0MQ infrastructure
        Context ctx = new Context(1);
        Socket s = ctx.Socket(SocketType.PUB);
        s.Connect(address);

        //  Create a message to send.
        byte[] msg = new byte[messageSize];

        //  Start sending messages.
        for (int i = 0; i < messageCount; i++)
            s.Send(msg);

        System.Threading.Thread.Sleep(10000);

        return 0;
    }
}