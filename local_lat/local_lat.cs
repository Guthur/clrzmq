
using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using System.Diagnostics;
using ZMQ;

class local_lat
{

    static unsafe int Main(string[] args)
    {
        if (args.Length != 3)
        {
            Console.Out.WriteLine("usage: local_lat <address> " +
                "<message-size> <roundtrip-count>\n");
            return 1;
        }

        String address = args[0];
        uint messageSize = Convert.ToUInt32(args[1]);
        int roundtripCount = Convert.ToInt32(args[2]);

        //  Initialise 0MQ infrastructure
        Context ctx = new Context(1);
        Socket s = ctx.Socket(SocketType.REP);
        s.Bind(address);

        //  Bounce the messages.
        for (int i = 0; i < roundtripCount; i++)
        {
            byte[] msg;
            s.Recv(out msg);
            Debug.Assert(msg.Length == messageSize);
            s.Send(msg);   
        }

        System.Threading.Thread.Sleep(2000);
        
        return 0;
    }
}