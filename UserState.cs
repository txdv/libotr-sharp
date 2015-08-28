//  Copyright (c) 2015 Mirco Bauer <meebey@meebey.net>
//
//  This library is free software; you can redistribute it and/or modify
//  it under the terms of the GNU Lesser General Public License as
//  published by the Free Software Foundation; either version 2.1 of the
//  License, or (at your option) any later version.
//
//  This library is distributed in the hope that it will be useful, but
//  WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
//  Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public
//  License along with this library; if not, write to the Free Software
//  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Linq;
using System.Linq.Expressions;

namespace Otr
{
    public sealed class ZipEntry<T1, T2>
    {
        public ZipEntry(int index, T1 value1, T2 value2)
        {
            Index = index;
            Value1 = value1;
            Value2 = value2;
        }

        public int Index { get; private set; }
        public T1 Value1 { get; private set; }
        public T2 Value2 { get; private set; }
    }

    public static class MethodExtensions
    {
        public static IEnumerable<ZipEntry<T1, T2>> Zip<T1, T2>(this IEnumerable<T1> collection1, IEnumerable<T2> collection2, bool exactSize = true)
        {
            if (collection1 == null) {
                throw new ArgumentNullException(nameof(collection1));
            }

            if (collection2 == null) {
                throw new ArgumentNullException(nameof(collection2));
            }

            int index = 0;
            using (IEnumerator<T1> enumerator1 = collection1.GetEnumerator())
            using (IEnumerator<T2> enumerator2 = collection2.GetEnumerator()) {
                if (exactSize) {
                    while (true) {
                        bool hasNext1 = enumerator1.MoveNext();
                        bool hasNext2 = enumerator2.MoveNext();
                        if (hasNext1 != hasNext2)
                            throw new InvalidOperationException("One of the collections ran " +
                            "out of values before the other");
                        if (!hasNext1)
                            break;

                        yield return new ZipEntry<T1, T2>(
                            index, enumerator1.Current, enumerator2.Current);
                        index++;
                    }
                } else {
                    while (enumerator1.MoveNext() && enumerator2.MoveNext()) {
                        yield return new ZipEntry<T1, T2>(index, enumerator1.Current, enumerator2.Current);
                        index++;
                    }
                }
            }
        }

        public static Delegate ToDelegate(this MethodInfo mi, object target)
        {
            if (mi == null) throw new ArgumentNullException("mi");

            Type delegateType;

            var typeArgs = mi.GetParameters()
                .Select(p => p.ParameterType)
                .ToList();

            // builds a delegate type
            if (mi.ReturnType == typeof(void)) {
                delegateType = Expression.GetActionType(typeArgs.ToArray());

            } else {
                typeArgs.Add(mi.ReturnType);
                delegateType = Expression.GetFuncType(typeArgs.ToArray());
            }

            // creates a binded delegate if target is supplied
            var result = (target == null)
                ? Delegate.CreateDelegate(delegateType, mi)
                : Delegate.CreateDelegate(delegateType, target, mi);

            return result;
        }

        public static bool SameInterface(this MethodInfo that, MethodInfo methodInfo)
        {
            return that.ReturnType == methodInfo.ReturnType &&
                !that.GetParameters().Zip(methodInfo.GetParameters()).Select(a => a.Value1.ParameterType == a.Value2.ParameterType).Contains(false);
            //Enumerable.SequenceEqual(that.GetParameters(), methodInfo.GetParameters());
        }
    }

    public class UserState : IDisposable
    {
        public IntPtr Handle { get; set; }
        private GCHandle GCHandle { get; set; }

        public UserState()
        {
            Handle = OtrApi.otrl_userstate_create();

            GCHandle = GCHandle.Alloc(this);
        }

        ~UserState()
        {
            GC.SuppressFinalize(this);
            Dispose();
        }

        public void Dispose()
        {
            var handle = Handle;
            if (handle == IntPtr.Zero) {
                return;
            }
            OtrApi.otrl_userstate_free(handle);
        }

        #region privkey

        unsafe bool Fill(ArraySegment<byte> segment, int minimumSize, Func<IntPtr, IntPtr> managedfunction)
        {
            if (segment.Count < minimumSize) {
                throw new ArgumentException("the segment needs to be at least 20 bytes big", nameof(segment));
            }

            fixed (byte* ptr = segment.Array) {
                var ret = managedfunction((IntPtr)ptr + segment.Offset);
                if (ret == null) {
                    return false;
                }
                return true;
            }
        }

        unsafe public bool FingerprintRaw(ArraySegment<byte> segment, string accountname, string protocol)
        {
            return Fill(segment, 20, (IntPtr pointer) => OtrApi.otrl_privkey_fingerprint_raw(Handle, pointer, accountname, protocol));
        }

        public byte[] FingerprintRaw(string accountname, string protocol)
        {
            var array = new byte[20];
            if (FingerprintRaw(new ArraySegment<byte>(array), accountname, protocol)) {
                return array;
            }
            return null;
        }

        unsafe public bool Fingerprint(ArraySegment<byte> segment, string accountname, string protocol)
        {
            return Fill(segment, OtrApi.OTRL_PRIVKEY_FPRINT_HUMAN_LEN - 1, (IntPtr pointer) => OtrApi.otrl_privkey_fingerprint(Handle, pointer, accountname, protocol));
        }

        public byte[] Fingerprint(string accountname, string protocol)
        {
            var array = new byte[OtrApi.OTRL_PRIVKEY_FPRINT_HUMAN_LEN - 1];
            if (Fingerprint(new ArraySegment<byte>(array), accountname, protocol)) {
                return array;
            }
            return null;
        }

        // TODO: make it not static, put it somewhere useful
        unsafe public void HashToHuman(ArraySegment<byte> hash, ArraySegment<byte> human)
        {
            if (hash.Count < 20) {
                throw new ArgumentException("hash has to be at least 20 bytes long", nameof(hash));
            }

            if (human.Count < 44) {
                throw new ArgumentException("buffer for the human readable format has to be at least 45 bytes long", nameof(human));
            }

            fixed (byte* humanp = human.Array)
            fixed (byte* hashp = hash.Array) {
                IntPtr humanpointer = (IntPtr)humanp + human.Offset;
                IntPtr hashpointer = (IntPtr)hashp + hash.Offset;
                OtrApi.otrl_privkey_hash_to_human(humanpointer, hashpointer);
            }
        }

        public void ReadPrivateKey(string filename)
        {
            int r = OtrApi.otrl_privkey_read(Handle, filename);
            //Console.WriteLine(GCryptApi.MessageFromErrorCode(r));
        }



        public void GeneratePrivateKey(string filename, string accountname, string protocol)
        {
            int r = OtrApi.otrl_privkey_generate(Handle, filename, accountname, protocol);
            //Console.WriteLine(GCryptApi.MessageFromErrorCode(r));

            r = OtrApi.otrl_privkey_write_fingerprints(Handle, string.Format("{0}.fingerprints", filename));
            //Console.WriteLine(GCryptApi.MessageFromErrorCode(r));
        }

        public IntPtr StartPrivateKeyGeneration(string accountname, string protocol)
        {
            IntPtr newkeyp;
            int r = OtrApi.otrl_privkey_generate_start(Handle, accountname, protocol, out newkeyp);
            //Console.WriteLine(GCryptApi.MessageFromErrorCode(r));
            Console.WriteLine("calculating");
            r = OtrApi.otrl_privkey_generate_calculate(newkeyp);
            //Console.WriteLine(GCryptApi.MessageFromErrorCode(r));
            return newkeyp;
        }

        public void ReadFingerprints(string filename)
        {
            int r = OtrApi.otrl_privkey_read_fingerprints(Handle, filename, null, IntPtr.Zero);
            //Console.WriteLine(GCryptApi.MessageFromErrorCode(r));
        }

        #endregion

        static unsafe string VersionString {
            get {
                return new string(OtrApi.otrl_version());
            }
        }

        static Version Version {
            get {
                return new Version(VersionString);
            }
        }

        static void Init()
        {
            var version = Version;
            int r = OtrApi.otrl_init((uint)version.Major, (uint)version.Minor, (uint)version.Revision);
            //Console.WriteLine(GCryptApi.MessageFromErrorCode(r));
        }

        static OtrApi.OtrlMessageAppOps ops = new OtrApi.OtrlMessageAppOps();
        static OtrApi.ManagedOtrlMessageAppOps mops = new OtrApi.ManagedOtrlMessageAppOps();

        static UserState()
        {
            Init();

            Assign.MethodsToDelegates<UserState, OtrApi.ManagedOtrlMessageAppOps>(ref mops);
            Assign.DelegatesToPointers<OtrApi.ManagedOtrlMessageAppOps, OtrApi.OtrlMessageAppOps>(mops, ref ops);
        }

        unsafe static void print(IntPtr ptr)
        {
            sbyte* b = (sbyte*)ptr;
            Console.WriteLine(*b);
        }

        unsafe public static void add_app_data(IntPtr data, IntPtr ConnContext)
        {
            var context = (OtrApi.context*)ConnContext;
        }

        unsafe public string MessageSending(string accountName, string protocol, string recipient, string message)
        {
            IntPtr contextp;
            IntPtr messagep; // this will contain the encrypted message
            int r = OtrApi.otrl_message_sending(
                Handle,
                ref ops,
                GCHandle.ToIntPtr(GCHandle), // opdata
                accountName,
                protocol,
                recipient,
                InstanceTag.Best,
                message,
                IntPtr.Zero, //otrltlv
                out messagep,
                OtrlFragmentPolicy.Skip,
                //ref NULL,
                out contextp,
                null,
                IntPtr.Zero
            );

            //Console.WriteLine(GCryptApi.MessageFromErrorCode(r));

            string encryptedMessage = Marshal.PtrToStringAnsi(messagep);
            OtrApi.otrl_message_free(messagep);
            return encryptedMessage;
        }

        unsafe public string MessageReceiving(string accountName, string protocol, string sender, string message)
        {
            IntPtr contextp;
            IntPtr newmessagep;
            int r = OtrApi.otrl_message_receiving(
                Handle,
                ref ops,
                GCHandle.ToIntPtr(GCHandle), // opdata
                accountName,
                protocol,
                sender,
                message,
                out newmessagep,
                IntPtr.Zero,
                out contextp,
                null,
                IntPtr.Zero
            );

            //Console.WriteLine(r);
            //Console.WriteLine(GCryptApi.MessageFromErrorCode(r));

            var decryptedMessage = Marshal.PtrToStringAnsi(newmessagep);
            OtrApi.otrl_message_free(newmessagep);
            return decryptedMessage;
        }

        static T As<T>(IntPtr pointer) where T : class
        {

            return GCHandle.FromIntPtr(pointer).Target as T;
        }

        protected void OnInjectMessage(string accountName, string protocol, string recipient, string message)
        {
            OnInjectMessage(new InjectMessageEventArgs(accountName, protocol, recipient, message));
        }

        protected void OnInjectMessage(InjectMessageEventArgs eventArgs)
        {
            if (InjectMessage != null) {
                InjectMessage(this, eventArgs);
            }
        }

        public void InstanceTagsRead(string filename)
        {
            int r = OtrApi.otrl_instag_read(Handle, filename);
            //Console.WriteLine(GCryptApi.MessageFromErrorCode(r));
        }

        public event EventHandler<InjectMessageEventArgs> InjectMessage;

        unsafe static OtrlPolicy policy(IntPtr opdata, IntPtr context)
        {
            Console.WriteLine("policy(opdata: {0}, context: {1})", opdata, context);
            return OtrlPolicy.Default;
        }

        unsafe static void create_privkey(IntPtr opdata, sbyte* accountname, sbyte* protocol)
        {
            Console.WriteLine("create_privkey");
        }

        unsafe static int is_logged_in(IntPtr opdata, sbyte* accountname, sbyte* protocol, sbyte* recipient)
        {
            Console.WriteLine("is_logged_in");
            return 0;
        }

        unsafe static void inject_message(IntPtr opdata, sbyte* accountname, sbyte* protocol, sbyte* recipient, sbyte* message)
        {
            Console.WriteLine("inject_message(opdata={0}, accountname=\"{1}\", protocol=\"{2}\", recipient=\"{3}\", message=\"{4}\")",
                opdata, new String(accountname), new string(protocol), new string(recipient), new string(message));

            As<UserState>(opdata).OnInjectMessage(new string(accountname), new string(protocol), new string(recipient), new string(message));
        }

        unsafe static void update_context_list(IntPtr opdata)
        {
            Console.WriteLine("update_context_list({0})", opdata);
        }

        unsafe static void new_fingerprint(IntPtr opdata, IntPtr us, sbyte* accountname, sbyte* protocol, sbyte* username, sbyte* fingerprint)
        {
            Console.WriteLine("new_fingerprint(opdata={0})", opdata);
        }

        static void write_fingerprints(IntPtr opdata)
        {
            Console.WriteLine("write_fingerprints(opdata={0})", opdata);
        }

        static void gone_secure(IntPtr opdata, IntPtr context)
        {
            Console.WriteLine("gone_secure(opdata={0}, context={1})", opdata, context);
        }

        static void gone_insecure(IntPtr opdata, IntPtr context)
        {
            Console.WriteLine("gone_insecure");
        }

        static void still_secure(IntPtr opdata, IntPtr context, int is_reply)
        {
            Console.WriteLine("still_secure");
        }

        /*
        static int max_message_size(IntPtr opdata, IntPtr context)
        {
            Console.WriteLine("max_message_size");
            return 512;
        }
        */

        unsafe static sbyte* account_name(IntPtr opdata, sbyte* account, sbyte* protocol)
        {
            Console.WriteLine("account_name");
            return (sbyte*)null;
        }

        unsafe static void received_symkey(IntPtr opdata, IntPtr context, uint use, byte* usedata, UIntPtr usedatalen, byte* symkey)
        {
            Console.WriteLine("received_symkey");
        }

        unsafe static sbyte* otr_error_message(IntPtr opdata, IntPtr context, OtrlErrorCode err_code)
        {
            Console.WriteLine("otr_error_message");
            return (sbyte*)null;
        }

        unsafe static void otr_error_message_free(IntPtr opdata, sbyte* err_msg)
        {
            Console.WriteLine("otr_error_message_free");
        }

        unsafe static sbyte* resent_msg_prefix(IntPtr opdata, IntPtr context)
        {
            Console.WriteLine("resent_msg_prefix");
            return (sbyte*)null;
        }

        unsafe static sbyte* resent_msg_prefix_free(IntPtr opdata, sbyte* prefix)
        {
            Console.WriteLine("resent_msg_prefix_free");
            return (sbyte*)null;
        }

        unsafe static void handle_smp_event(IntPtr opdata, OtrlSMPEvent smp_event, IntPtr context, ushort progress_percent, sbyte* question)
        {
            Console.WriteLine("handle_smp_event");
        }

        unsafe static void handle_msg_event(IntPtr opdata, OtrlMessageEvent msg_event, IntPtr context, sbyte* message, gcry_error_t err)
        {
            Console.WriteLine("handle_msg_event(opdata={0}, msg_event={1}, context={2}, message={3}, err={4})", opdata, msg_event, context, new string(message), err);
        }

        unsafe static void create_instag(IntPtr opdata, sbyte* accountname, sbyte* protocol)
        {
            Console.WriteLine("create_instag(opdate: {0}, accountname: {1}, protocol: {2})", opdata, GetStringFromReference(&accountname), GetStringFromReference(&protocol));

            As<UserState>(opdata).CreateInstag(new string(accountname), new string(protocol));
        }

        void CreateInstag(string accountname, string protocol)
        {
            OtrApi.otrl_instag_generate(Handle, "/dev/null", accountname, protocol);
            OtrApi.otrl_instag_write(Handle, string.Format("{0}.instag", accountname));
        }

        /*
        unsafe static void convert_msg(IntPtr opdata, IntPtr context, OtrlConvertType convert_type, sbyte** dest, sbyte* src)
        {
            Console.WriteLine("convert_msg(opdata: {0}, context: {1}, convert_type: {2}, dest: {3}, src: {4})",
                opdata, context, convert_type, GetStringFromReference(dest), GetStringFromReference(&src));
        }*/

        unsafe static void convert_free(IntPtr opdata, IntPtr context, sbyte* dest)
        {
            Console.WriteLine("convert_free");
        }

        unsafe static void timer_control(IntPtr opdata, uint interval)
        {
            Console.WriteLine("timer_control(opdata={0}, interval={1})", opdata, interval);
        }

        unsafe static object GetFromReference(sbyte** str)
        {
            if (str == (sbyte**)null) {
                return null;
            } else {
                return new string((sbyte*)*str);
            }
        }

        unsafe static string GetStringFromReference(sbyte** str)
        {
            var o = GetFromReference(str);
            if (o == null) {
                return "(null)";
            } else {
                return string.Format("\"{0}\"", o as string);
            }
        }
    }

    public class InjectMessageEventArgs : EventArgs
    {
        public InjectMessageEventArgs(string accountName, string protocol, string recipient, string message)
        {
            AccountName = accountName;
            Protocol = protocol;
            Recipient = recipient;
            Message = message;
        }

        public string AccountName { get; set; }
        public string Protocol { get; set; }
        public string Recipient { get; set; }
        public string Message { get; set; }
    }
}
