using System;
using Scrypt;
namespace ScryptManaged.ScryptTester
{
    public class Program
    {
        static void Main(string[] args)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("Here we go...");
            TestCases tc = new TestCases();
            byte[] result = null;
            //byte[] result2 = null;
            string encOut1 = null;
            string encOut2 = null;
            System.Diagnostics.Stopwatch sw = new System.Diagnostics.Stopwatch();
            for (int i = 0; i < tc.Cases.Length; i++)
            {
                sw.Reset();
                sw.Start();
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine("N=" + tc.Cases[i].N + ", r=" + tc.Cases[i].r + ", p=" + tc.Cases[i].p + ", outLen = " + tc.Cases[i].OutLen);
                result = null;
                encOut1 = null;
                encOut2 = null;
                try
                {
                    result = Scrypt.ComputeDerivedHash(tc.Cases[i].P, tc.Cases[i].S, tc.Cases[i].N, tc.Cases[i].r, tc.Cases[i].p, tc.Cases[i].OutLen);
                    //result2 = ScryptEncoder.CryptoScrypt(tc.Cases[i].P, tc.Cases[i].S, tc.Cases[i].N, tc.Cases[i].r, tc.Cases[i].p, tc.Cases[i].OutLen);
                    encOut1 = Scrypt.Encode(tc.Cases[i].P, tc.Cases[i].S, tc.Cases[i].N, tc.Cases[i].r, tc.Cases[i].p, tc.Cases[i].OutLen);
                    ScryptEncoder se = new ScryptEncoder(tc.Cases[i].N, tc.Cases[i].r, tc.Cases[i].p, tc.Cases[i].OutLen, tc.Cases[i].S);
                    encOut2 = se.Encode(tc.Cases[i].P);
                    Console.WriteLine("Encoded outputs:");
                    Console.WriteLine(encOut1);
                    Console.WriteLine(encOut2);
                    bool compareTest = Scrypt.Compare(encOut1, tc.Cases[i].P);
                    Console.WriteLine("Encoded outputs Compare: " + compareTest.ToString());
                }
                catch(Exception ex)
                {
                    result = null;
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("Exception: " + ex.Message
#if DEBUG                       
                        + "\r\n" + ex.StackTrace
#endif
                        );
                }
                Console.WriteLine(BytesToString(result));
                if (!CompareArrays(result, tc.Cases[i].Result))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("***FAIL!***");
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("---PASS---");
                } //*/
                /*if (!CompareArrays(result, result2))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("***FAIL COMPARISON!***");
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("---PASS COMPARISON---");
                } //*/
                sw.Stop();
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine(sw.Elapsed);
            }
            while (Console.KeyAvailable) { Console.ReadKey(true); }
            Console.WriteLine("Press ENTER to exit...");
            Console.ReadLine();
        }

        static string BytesToString(byte[] data)
        {
            if (data == null) return "[NULL]";
            return BitConverter.ToString(data).Replace("-", " ").ToLower();
        }

        static bool CompareArrays(byte[] a, byte[] b)
        {
            if (a == null && b == null)
                return true;
            if (a == null || b == null) // the AND condition has already been tested, so they must be different if one is null and not the other
                return false;
            string aa = BytesToString(a);
            string bb = BytesToString(b);
            return aa.CompareTo(bb) == 0;
        }

    }
}
