using System;
using System.Runtime.InteropServices;

namespace Otr
{
    public enum InstanceTag
    {
        Master,
        Best,
        Recent,
        Received,
        Sent
    }

    public enum OtrlFragmentPolicy {
        Skip,
        All,
        AllButFirst,
        AllButLast
    }

    public enum OtrlPolicy
    {
        AllowVersion1 = 0x01,
        AllowVersion2 = 0x02,
        AllowVersion3 = 0x04,
        RequireEncryption = 0x08,
        SendWhitespaceTag = 0x10,
        WhitespaceStartAke = 0x20,
        ErrorStartAke = 0x40,
        VersionMask = AllowVersion1 | AllowVersion2 | AllowVersion3,
        Never = 0x00,
        Opportunistic = AllowVersion2 | AllowVersion3 | SendWhitespaceTag | WhitespaceStartAke | ErrorStartAke,
        Manual = AllowVersion2 | AllowVersion3,
        Always = AllowVersion2 | AllowVersion3 | RequireEncryption | WhitespaceStartAke | ErrorStartAke,
        Default = Opportunistic
    };

    public enum OtrlSMPEvent
    {
        None,
        Error,
        Abort,
        Cheated,
        AskForAnswer,
        AskForSecret,
        InProgress,
        Success,
        Failure
    };

    public enum OtrlMessageEvent
    {
        None,
        EncryptionRequired,
        EncryptionError,
        ConnectionEnded,
        SetupError,
        MessageReflected,
        MessageResent,
        ReceivedMessageNotInPrivate,
        ReceivedMessageUnreadable,
        ReceivedMessageMalformed,
        LogHeartbeatReceived,
        LogHeartbeatSent,
        ReceivedMessageGeneralError,
        ReceivedMessageUnencrypted,
        ReceivedMessageUnrecognized,
        ReceivedMessageForOtherInstance
    };

    public enum OtrlConvertType
    {
        Sending,
        Receiving
    };

    public enum gcry_error_t : int
    {
    }

    public enum OtrlMessageState
    {
        /// <summary>
        /// Not yet started an encrypted encryption.
        /// </summary>
        Plaintext,
        /// <summary>
        /// Currently in an encrypted conversation.
        /// </summary>
        Encrypted,
        /// <summary>
        /// The remote side has sent us a notification that he has
        /// ended his end of the encrypted conversation; prevent any
        /// further messages from being sent to him.
        /// </summary>
        Finished
    };

    public enum OtrlAuthState {
        None,
        AwaitingDHKey,
        AwaitingRevealSIG,
        AwaitingSIG,
        V1Setup
    };

    // src/mpi.h:65
    public struct gcry_mpi
    {
        int alloced;
        int nlimbs;
        int sign;

        uint flags;

        // TODO: this is of type mpi_limit_t
        // but thank god we dont need to implement it
        // until it is really relevant (the rabbit hole was already
        // deep enough as it is)
        IntPtr d;
    };

    public struct DH_keypair {
        public int groupid;
        public gcry_mpi priv;
        public gcry_mpi pub;
    };

    unsafe public static class OtrApi
    {
        public struct OtrlAuthInfo
        {
            public OtrlAuthState authstate;
            public context* context;

            public DH_keypair our_dh;
            public uint our_keyid;

            public sbyte* encgx;
            public IntPtr encgx_len;
            public fixed byte r[16];

            public fixed byte hashgx[32];

            public gcry_mpi their_pub;
            public uint their_keyid;
        }

        public struct s_fingerprint {
            /// <summary>
            /// The next fingerprint in the list
            /// </summary>
            public IntPtr next;
            /// <summary>
            /// A pointer to the pointer to us
            /// </summary>
            public IntPtr tous;
            /// <summary>
            /// The fingerprint, or NULL
            /// </summary>
            public byte* fingerprint;
            /// <summary>
            /// The context to which we belong
            /// </summary>
            public context* context;
            /// <summary>
            /// The trust level of the fingerprint
            /// </summary>
            public sbyte* trust;
        };

        public struct context
        {
            public IntPtr next;
            public IntPtr tous;

            public IntPtr context_priv;

            public sbyte* username;
            public sbyte* accountname;
            public sbyte* protocol;

            // the followign IntPtrs are all contexts

            public IntPtr m_context;
            public IntPtr recent_rcvd_child;
            public IntPtr recent_sent_child;
            public IntPtr recent_child;

            public InstanceTag our_instance;
            public InstanceTag their_instance;

            public OtrlMessageState msgstate;

            public OtrlAuthInfo auth;

            public s_fingerprint fingerprint_auth;
            public s_fingerprint *active_fingerprint;

            public fixed byte sessionid[20];
            public IntPtr sessionid_len;

            public OtrlSessionIdHalf sessionid_half;
            public uint protocol_version;

            /// <summary>
            /// Has this correspondent repsponded to our OTR offers?
            /// </summary>
            public OtrOffer offer;

            /// <summary>
            /// Application data to be associated with this context
            /// </summary>
            public IntPtr app_data;
            /// <summary>
            /// A function to free the above data when we forget this context
            /// </summary>
            public IntPtr app_data_free;

            // TODO: this has a type, i'm too lazyu now to type everything out
            public IntPtr smstate;
        }

        public enum OtrOffer {
            Not,
            Sent,
            Rejected,
            Accepted
        };

        public struct OtrlSessionIdHalf
        {

        };

        public delegate OtrlPolicy policy(IntPtr opdata, IntPtr context);
        public delegate void create_privkey(IntPtr opdata, sbyte* accountname, sbyte* protocol);
        public delegate int is_logged_in(IntPtr opdata, sbyte* accountname, sbyte* protocol, sbyte* recipient);
        public delegate void inject_message(IntPtr opdata, sbyte* accountname, sbyte* protocol, sbyte* recipient, sbyte* message);
        public delegate void update_context_list(IntPtr opdata);
        public delegate void new_fingerprint(IntPtr opdata, IntPtr us, sbyte* accountname, sbyte* protocol, sbyte* username, sbyte* fingerprint);
        public delegate void write_fingerprints(IntPtr opdata);
        public delegate void gone_secure(IntPtr opdata, IntPtr context);
        public delegate void gone_insecure(IntPtr opdata, IntPtr context);
        public delegate void still_secure(IntPtr opdata, IntPtr context, int is_reply);
        public delegate int max_message_size(IntPtr opdata, IntPtr context);
        public delegate sbyte* account_name(IntPtr opdata, sbyte* account, sbyte* protocol);
        public delegate void account_name_free(IntPtr opdata, sbyte* account_name);
        public delegate void received_symkey(IntPtr opdata, IntPtr context, uint use, byte* usedata, UIntPtr usedatalen, byte* symkey);
        public delegate sbyte* otr_error_message(IntPtr opdata, IntPtr context, OtrlErrorCode err_code);
        public delegate void otr_error_message_free(IntPtr opdata, sbyte* err_msg);
        public delegate sbyte* resent_msg_prefix(IntPtr opdata, IntPtr context);
        public delegate sbyte* resent_msg_prefix_free(IntPtr opdata, sbyte* prefix);
        public delegate void handle_smp_event(IntPtr opdata, OtrlSMPEvent smp_event, IntPtr context, ushort progress_percent, sbyte* question);
        public delegate void handle_msg_event(IntPtr opdata, OtrlMessageEvent msg_event, IntPtr context, sbyte* message, gcry_error_t err);
        public delegate void create_instag(IntPtr opdata, sbyte* accountname, sbyte* protocol);
        public delegate void convert_msg(IntPtr opdata, IntPtr context, OtrlConvertType convert_type, sbyte** dest, sbyte* src);
        public delegate void convert_free(IntPtr opdata, IntPtr context, sbyte* dest);
        public delegate void timer_control(IntPtr opdata, uint interval);

        public struct ManagedOtrlMessageAppOps
        {
            public policy policy;
            public create_privkey create_privkey;
            public is_logged_in is_logged_in;
            public inject_message inject_message;
            public update_context_list update_context_list;
            public new_fingerprint new_fingerprint;
            public write_fingerprints write_fingerprints;
            public gone_secure gone_secure;
            public gone_insecure gone_insecure;
            public still_secure still_secure;
            public max_message_size max_message_size;
            public account_name account_name;
            public account_name_free account_name_free;
            public received_symkey received_symkey;
            public otr_error_message otr_error_message;
            public otr_error_message_free otr_error_message_free;
            public resent_msg_prefix resent_msg_prefix;
            public resent_msg_prefix_free resent_msg_prefix_free;
            public handle_smp_event handle_smp_event;
            public handle_msg_event handle_msg_event;
            public create_instag create_instag;
            public convert_msg convert_msg;
            public convert_free convert_free;
            public timer_control timer_control;
        }

        public struct OtrlMessageAppOps
        {
            public IntPtr policy;
            public IntPtr create_privkey;
            public IntPtr is_logged_in;
            public IntPtr inject_message;
            public IntPtr update_context_list;
            public IntPtr new_fingerprint;
            public IntPtr write_fingerprints;
            public IntPtr gone_secure;
            public IntPtr gone_insecure;
            public IntPtr still_secure;
            public IntPtr max_message_size;
            public IntPtr account_name;
            public IntPtr account_name_free;
            public IntPtr received_symkey;
            public IntPtr otr_error_message;
            public IntPtr otr_error_message_free;
            public IntPtr resent_msg_prefix;
            public IntPtr resent_msg_prefix_free;
            public IntPtr handle_smp_event;
            public IntPtr handle_msg_event;
            public IntPtr create_instag;
            public IntPtr convert_msg;
            public IntPtr convert_free;
            public IntPtr timer_control;
        }

        public struct OtrlTLV
        {
            //unsigned short type;
            public ushort Type;
            //unsigned short len;
            public ushort Length;
            //unsigned char *data;
            public IntPtr Data;
            //struct s_OtrlTLV *next;
            public IntPtr Next;
        }


		//void otrl_message_free(char *message);
		/// <summary>
		/// Deallocate a message allocated by other otrl_message_* routines.
		/// </summary>
		[DllImport("libotr.so.5")]
		public static extern void otrl_message_free(IntPtr message);

        // int otrl_message_receiving(OtrlUserState us, const OtrlMessageAppOps *ops, void *opdata,
        //   const char *accountname, const char *protocol, const char *sender, const char *message, char **newmessagep,
        //   OtrlTLV **tlvsp, ConnContext **contextp, void (*add_appdata)(void *data, ConnContext *context), void *data);

        [DllImport("libotr.so.5")]
        public static extern int otrl_message_receiving(
            IntPtr userState,
            ref OtrlMessageAppOps messageAppOps,
            IntPtr opData,
            string accountName,
            string protocol,
            string sender,
            string message,
            out IntPtr newmessagep,
            IntPtr tlvsp,
            out IntPtr contextp,
            add_app_data add_app_data,
            IntPtr data
        );

		// void otrl_message_disconnect(OtrlUserState us, const OtrlMessageAppOps *ops,
		// 	void *opdata, const char *accountname, const char *protocol,
		// 	const char *username, otrl_instag_t instance);

		// void otrl_message_disconnect_all_instances(OtrlUserState us,
		// 	const OtrlMessageAppOps *ops, void *opdata, const char *accountname,
		// 	const char *protocol, const char *username);

		// void otrl_message_initiate_smp(OtrlUserState us, const OtrlMessageAppOps *ops,
		// 	void *opdata, ConnContext *context, const unsigned char *secret, size_t secretlen);

		// void otrl_message_initiate_smp_q(OtrlUserState us,
		// 	const OtrlMessageAppOps *ops, void *opdata, ConnContext *context,
		// 	const char *question, const unsigned char *secret, size_t secretlen);

		// void otrl_message_respond_smp(OtrlUserState us, const OtrlMessageAppOps *ops,
		// 	void *opdata, ConnContext *context, const unsigned char *secret, size_t secretlen);

		// void otrl_message_abort_smp(OtrlUserState us, const OtrlMessageAppOps *ops, void *opdata, ConnContext *context);

		// gcry_error_t otrl_message_symkey(OtrlUserState us,
		// 	const OtrlMessageAppOps *ops, void *opdata, ConnContext *context,
		// 	unsigned int use, const unsigned char *usedata, size_t usedatalen,
		// 	unsigned char *symkey);

		// unsigned int otrl_message_poll_get_default_interval(OtrlUserState us);

		// void otrl_message_poll(OtrlUserState us, const OtrlMessageAppOps *ops, void *opdata);

		// OtrlUserState otrl_userstate_create(void);
		/// <summary>
		/// Create a new OtrlUserState.  Most clients will only need one of
		/// these.  A OtrlUserState encapsulates the list of known fingerprints
		/// and the list of private keys; if you have separate files for these
		/// things for (say) different users, use different OtrlUserStates.  If
		/// you've got only one user, with multiple accounts all stored together
		/// in the same fingerprint store and privkey store files, use just one
		/// OtrlUserState.
		/// </summary>
		[DllImport("libotr.so.5")]
		public static extern IntPtr otrl_userstate_create();

		/// <summary>
		/// Free a OtrlUserState.  If you have a timer running for this userstate,
		/// stop it before freeing the userstate.
		/// </summary>
        [DllImport("libotr.so.5")]
        public static extern void otrl_userstate_free(IntPtr userState);

#region TLV
        /* Make a single TLV, copying the supplied data */
        //OtrlTLV *otrl_tlv_new(unsigned short type, unsigned short len, const unsigned char *data);
        [DllImport("libotr.so.5")]
        public static extern IntPtr otrl_tlv_new(ushort type, ushort length, IntPtr data);
        public static IntPtr otrl_tlv_new(ushort type, byte[] data)
        {
            var unmanagedPointer = Marshal.AllocHGlobal(data.Length);
            Marshal.Copy(data, 0, unmanagedPointer, data.Length);
            var res = otrl_tlv_new(type, (ushort) data.Length, unmanagedPointer);
            Marshal.FreeHGlobal(unmanagedPointer);
            return res;
        }


        /* Construct a chain of TLVs from the given data */
        //OtrlTLV *otrl_tlv_parse(const unsigned char *serialized, size_t seriallen);

        /* Deallocate a chain of TLVs */
        //void otrl_tlv_free(OtrlTLV *tlv);

        /* Find the serialized length of a chain of TLVs */
        //size_t otrl_tlv_seriallen(const OtrlTLV *tlv);

        /* Serialize a chain of TLVs.  The supplied buffer must already be large
 * enough. */
        //void otrl_tlv_serialize(unsigned char *buf, const OtrlTLV *tlv);

        /* Return the first TLV with the given type in the chain, or NULL if one
 * isn't found.  (The tlvs argument isn't const because the return type
 * needs to be non-const.) */
        //OtrlTLV *otrl_tlv_find(OtrlTLV *tlvs, unsigned short type);
#endregion

        /* Read a sets of private DSA keys from a file on disk into the given
 * OtrlUserState. */
        //gcry_error_t otrl_privkey_read(OtrlUserState us, const char *filename)

        #region privkey

        public static readonly int OTRL_PRIVKEY_FPRINT_HUMAN_LEN = 45 - 1;

        [DllImport("libotr.so.5")]
        public static extern IntPtr otrl_privkey_fingerprint(IntPtr us, IntPtr fingerprint, string accountname, string protocol);

        [DllImport("libotr.so.5")]
        public static extern IntPtr otrl_privkey_fingerprint_raw(IntPtr us, IntPtr hash, string accountname, string protocol);

        [DllImport("libotr.so.5")]
        public static extern IntPtr otrl_privkey_hash_to_human(IntPtr human, IntPtr hash);

        [DllImport("libotr.so.5")]
        public static extern int otrl_privkey_read(IntPtr us, string filename);

        //gcry_error_t otrl_privkey_generate(OtrlUserState us, const char *filename,
        //            const char *accountname, const char *protocol)

        [DllImport("libotr.so.5")]
        public static extern int otrl_privkey_generate(IntPtr us, string filename, string accountname, string protocol);

        [DllImport("libotr.so.5")]
        public static extern int otrl_privkey_generate_start(IntPtr us, string accountname, string protocol, out IntPtr newkeyp);

        [DllImport("libotr.so.5")]
        public static extern int otrl_privkey_generate_calculate(IntPtr newkeyp);

        [DllImport("libotr.so.5")]
        public static extern int otrl_privkey_write_fingerprints(IntPtr us, string filename);

        public delegate void add_app_data(IntPtr data, IntPtr ConnContext);

        //gcry_error_t otrl_privkey_read_fingerprints(OtrlUserState us,
        //    const char *filename,
        //    void (*add_app_data)(void *data, ConnContext *context),
        //    void  *data)
        [DllImport("libotr.so.5")]
        public static extern int otrl_privkey_read_fingerprints(IntPtr us, string filename, add_app_data add_app_data, IntPtr data);

        #endregion

        /*
            OtrlUserState us
            const OtrlMessageAppOps *ops
            void *opdata
            const char *accountname
            const char *protocol
            const char *sender
            const char *message
            char **newmessagep
            OtrlTLV **tlvsp
            ConnContext **contextp
            void (*add_appdata)(void *data, ConnContext *context),
            void *data);
        */

        /*
            OtrlUserState us,
            const OtrlMessageAppOps *ops,
            void *opdata
            const char *accountname
            const char *protocol
            const char *recipient
            otrl_instag_t instag
            const char *original_msg
            OtrlTLV *tlvs
            char **messagep
            OtrlFragmentPolicy fragPolicy
            ConnContext **contextp
            void (*add_appdata)(void *data, ConnContext *context)
            void *data
        */
        /*
        gcry_error_t otrl_message_sending(OtrlUserState us,
            const OtrlMessageAppOps *ops,
            void *opdata, const char *accountname, const char *protocol,
            const char *recipient, otrl_instag_t instag, const char *original_msg,
            OtrlTLV *tlvs, char **messagep, OtrlFragmentPolicy fragPolicy,
            ConnContext **contextp,
            void (*add_appdata)(void *data, ConnContext *context),
            void *data);
        */

        [DllImport("libotr.so.5")]
        unsafe public static extern int otrl_message_sending(
            IntPtr us,
            ref OtrlMessageAppOps ops,
            IntPtr opdata,
            string accountname,
            string protocol,
            string recipient,
            InstanceTag instag,
            string original_msg,
            //ref OtrlTLV tlvs,
            IntPtr tlvs,
            out IntPtr messagep,
            OtrlFragmentPolicy fragPolicy,
            //ref IntPtr contextp,
            out IntPtr contextp,
            add_app_data add_app_data,
            IntPtr data
        );

        [DllImport("libotr.so.5")]
        unsafe public static extern sbyte* otrl_version();

        [DllImport("libotr.so.5")]
        unsafe public static extern int otrl_init(uint ver_major, uint ver_minor, uint ver_sub);

        [DllImport("__Internal")]
        unsafe public static extern int printf(IntPtr ptr);

        [DllImport("__Internal")]
        unsafe public static extern int strlen(IntPtr ptr);

        #region Instance Tags

        [DllImport("libotr.so.5")]
        unsafe public static extern int otrl_instag_generate(IntPtr us, string filename, string accountname, string protocol);

        [DllImport("libotr.so.5")]
        unsafe public static extern int otrl_instag_write(IntPtr us, string filename);

        [DllImport("libotr.so.5")]
        unsafe public static extern int otrl_instag_read(IntPtr us, string filename);

        #endregion

        #region Query

        [DllImport("libotr.so.5")]
        unsafe public static extern sbyte* otrl_proto_default_query_msg(string ourname, OtrlPolicy policy);

        [DllImport("libotr.so.5")]
        unsafe public static extern int otrl_proto_query_bestversion(string querymsg, OtrlPolicy policy);

        #endregion
    }


    /*
    #define OTRL_INSTAG_MASTER 0
    #define OTRL_INSTAG_BEST 1 /* Most secure, based on: conv status,
    #define OTRL_INSTAG_RECENT 2
    #define OTRL_INSTAG_RECENT_RECEIVED 3
    #define OTRL_INSTAG_RECENT_SENT 4
    */


    class GCryptApi
    {
        [DllImport("gcrypt.so.11")]
        unsafe public static extern sbyte* gcry_strerror(int errorCode);

        unsafe public static string MessageFromErrorCode(int errorCode)
        {
            return new string(gcry_strerror(errorCode));
        }
    }
}
