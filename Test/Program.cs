using System;
using Otr;
using System.IO;

namespace Test
{
    unsafe class MainClass
    {
        static void GenerateKey(UserState userState, string accountname, string protocol, string filename)
        {
            if (File.Exists(filename)) {
                userState.ReadPrivateKey(filename);
            } else {
                Console.WriteLine("Generating key, this might take a while, please wait");
                userState.GeneratePrivateKey(filename, accountname, protocol);
            }
        }

        static UserState us1 = new UserState();
        static UserState us2 = new UserState();

        static string protocol = "protocol";

        public static void Main(string[] args)
        {
            GenerateKey(us1, "us1", protocol, "us1");
            us1.ReadFingerprints("us1.fingerprints");

            var us2 = new UserState();
            GenerateKey(us2, "us2", protocol, "us2");
            us2.ReadFingerprints("us2.fingerprints");

            var message1 = us1.MessageSending("us1", protocol, "us2", "");
            us2.InjectMessage += (sender, e) => {
                us1.InjectMessage += (sender2, e2) => {
                    us2.MessageReceiving("us2", protocol, "us1", e2.Message);
                };
                us1.MessageReceiving("us1", protocol, "us2", e.Message);
            };
            us2.MessageReceiving("us2", protocol, "us1", message1);

            string msg;

            msg = us1.MessageSending("us1", "protocol", "us2", "Hello World!");
            Console.WriteLine("Encrypted: {0}", msg);
            msg = us2.MessageReceiving("us2", "protocol", "us1", msg);
            Console.WriteLine("Plaintext: {0}", msg);

            msg = us2.MessageSending("us2", "protocol", "us1", "I am not the world, but hello to you too!");
            Console.WriteLine(msg);
            msg = us1.MessageReceiving("us1", "protocol", "us2", msg);
            Console.WriteLine(msg);
       }
    }
}

