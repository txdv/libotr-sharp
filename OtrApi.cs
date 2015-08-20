using System;
using System.Runtime.InteropServices;

namespace Otr
{
	public static class OtrApi
	{
		struct OtrlMessageAppOps
		{
            //OtrlPolicy (*policy)(void *opdata, ConnContext *context);
            //// <summary>
            /// Return the OTR policy for the given context.
            /// </summary>
            IntPtr Policy;

            //void (*create_privkey)(void *opdata, const char *accountname, const char *protocol);
            /// <summary>
            ///  Create a private key for the given accountname/protocol if
            /// desired.
            /// </summary>
            IntPtr CreatePrivateKey;

            //int (*is_logged_in)(void *opdata, const char *accountname, const char *protocol, const char *recipient);
            /// <summary>
            /// Report whether you think the given user is online.  Return 1 if
            /// you think he is, 0 if you think he isn't, -1 if you're not sure.
            ///
            /// If you return 1, messages such as heartbeats or other
            /// notifications may be sent to the user, which could result in "not
            /// logged in" errors if you're wrong.
            /// </summary>
            IntPtr IsLoggedIn;

            //void (*inject_message)(void *opdata, const char *accountname, const char *protocol, const char *recipient, const char *message);
            /// <summary>
            /// Send the given IM to the given recipient from the given
            /// accountname/protocol.
            /// </summary>
            IntPtr InjectMessage;

            //void (*update_context_list)(void *opdata);
            /// <summary>
            /// When the list of ConnContexts changes (including a change in
            /// state), this is called so the UI can be updated.
            /// </summary>
            IntPtr UpdateContextList;

            //void (*new_fingerprint)(void *opdata, OtrlUserState us, const char *accountname, const char *protocol, const char *username, unsigned char fingerprint[20]);
            /// <summary>
            /// A new fingerprint for the given user has been received.
            /// </summary>
            IntPtr NewFingerprint;

            //void (*write_fingerprints)(void *opdata);
            /// <summary>
            /// The list of known fingerprints has changed.  Write them to disk.
            /// </summary>
            IntPtr WriteFingerprints;

            //void (*gone_secure)(void *opdata, ConnContext *context);
            /// <summary>
            /// A ConnContext has entered a secure state.
            /// </summary>
            IntPtr GoneSecure;

            //void (*gone_insecure)(void *opdata, ConnContext *context);
            /// <summary>
            /// A ConnContext has left a secure state.
            /// </summary>
            IntPtr GoneInsecure;

            //void (*still_secure)(void *opdata, ConnContext *context, int is_reply);
            /// <summary>
            /// We have completed an authentication, using the D-H keys we
            /// already knew.  is_reply indicates whether we initiated the AKE.
            /// </summary>
            IntPtr StillSecure;

            //int (*max_message_size)(void *opdata, ConnContext *context);
            /// <summary>
            /// Find the maximum message size supported by this protocol. */
            /// </summary>
            IntPtr MaxMessageSize;

            //const char *(*account_name)(void *opdata, const char *account, const char *protocol);
            /// <summary>
            /// Return a newly allocated string containing a human-friendly
            /// representation for the given account
            /// </summary>
            IntPtr AccountName;

            //void (*account_name_free)(void *opdata, const char *account_name);
            /// <summary>
            /// Deallocate a string returned by account_name
            /// </summary>
            IntPtr AccountNameFree;

            //void (*received_symkey)(void *opdata, ConnContext *context, unsigned int use, const unsigned char *usedata, size_t usedatalen, const unsigned char *symkey);
            /// <summary>
            /// We received a request from the buddy to use the current "extra"
            /// symmetric key.  The key will be passed in symkey, of length
            /// OTRL_EXTRAKEY_BYTES.  The requested use, as well as use-specific
            /// data will be passed so that the applications can communicate other
            /// information (some id for the data transfer, for example). */
            /// </summary>
            IntPtr ReceivedSymkey;

            //const char *(*otr_error_message)(void *opdata, ConnContext *context, OtrlErrorCode err_code);
            /// <summary>
            /// Return a string according to the error event. This string will then
            /// be concatenated to an OTR header to produce an OTR protocol error
            /// message. The following are the possible error events:
            /// - OTRL_ERRCODE_ENCRYPTION_ERROR
            ///      occured while encrypting a message
            /// - OTRL_ERRCODE_MSG_NOT_IN_PRIVATE
            ///      sent encrypted message to somebody who is not in
            ///      a mutual OTR session
            /// - OTRL_ERRCODE_MSG_UNREADABLE
            ///      sent an unreadable encrypted message
            /// - OTRL_ERRCODE_MSG_MALFORMED
            ///      message sent is malformed
            /// </summary>
            IntPtr OtrErrorMessage;

            //void (*otr_error_message_free)(void *opdata, const char *err_msg);
            /// <summary>
            /// Deallocate a string returned by otr_error_message
            /// </summary>
            IntPtr OtrErrorMessageFree;

            //const char *(*resent_msg_prefix)(void *opdata, ConnContext *context);
            /// <summary>
            /// Return a string that will be prefixed to any resent message. If this
            /// function is not provided by the application then the default prefix,
            /// "[resent]", will be used.
            /// </summary>
            IntPtr ResentMessagePrefix;

            //void (*resent_msg_prefix_free)(void *opdata, const char *prefix);
            /// <summary>
            /// Deallocate a string returned by resent_msg_prefix
            /// </summary>
            IntPtr ResentMessagePrefixFree;

            //void (*handle_smp_event)(void *opdata, OtrlSMPEvent smp_event, ConnContext *context, unsigned short progress_percent, char *question);
            /// <summary>
            /// Update the authentication UI with respect to SMP events
            /// These are the possible events:
            /// - OTRL_SMPEVENT_ASK_FOR_SECRET
            ///      prompt the user to enter a shared secret. The sender application
            ///      should call otrl_message_initiate_smp, passing NULL as the question.
            ///      When the receiver application resumes the SM protocol by calling
            ///      otrl_message_respond_smp with the secret answer.
            /// - OTRL_SMPEVENT_ASK_FOR_ANSWER
            ///      (same as OTRL_SMPEVENT_ASK_FOR_SECRET but sender calls
            ///      otrl_message_initiate_smp_q instead)
            /// - OTRL_SMPEVENT_CHEATED
            ///      abort the current auth and update the auth progress dialog
            ///      with progress_percent. otrl_message_abort_smp should be called to
            ///      stop the SM protocol.
            /// - OTRL_SMPEVENT_INPROGRESS   and
            ///   OTRL_SMPEVENT_SUCCESS      and
            ///   OTRL_SMPEVENT_FAILURE      and
            ///   OTRL_SMPEVENT_ABORT
            ///      update the auth progress dialog with progress_percent
            /// - OTRL_SMPEVENT_ERROR
            ///      (same as OTRL_SMPEVENT_CHEATED)
            /// </summary>
            IntPtr HandleSmpEvent;

            //void (*handle_msg_event)(void *opdata, OtrlMessageEvent msg_event, ConnContext *context, const char *message, gcry_error_t err);
            /// <summary>
            /// Handle and send the appropriate message(s) to the sender/recipient
            /// depending on the message events. All the events only require an opdata,
            /// the event, and the context. The message and err will be NULL except for
            /// some events (see below). The possible events are:
            /// - OTRL_MSGEVENT_ENCRYPTION_REQUIRED
            ///      Our policy requires encryption but we are trying to send
            ///      an unencrypted message out.
            /// - OTRL_MSGEVENT_ENCRYPTION_ERROR
            ///      An error occured while encrypting a message and the message
            ///      was not sent.
            /// - OTRL_MSGEVENT_CONNECTION_ENDED
            ///      Message has not been sent because our buddy has ended the
            ///      private conversation. We should either close the connection,
            ///      or refresh it.
            /// - OTRL_MSGEVENT_SETUP_ERROR
            ///      A private conversation could not be set up. A gcry_error_t
            ///      will be passed.
            /// - OTRL_MSGEVENT_MSG_REFLECTED
            ///      Received our own OTR messages.
            /// - OTRL_MSGEVENT_MSG_RESENT
            ///      The previous message was resent.
            /// - OTRL_MSGEVENT_RCVDMSG_NOT_IN_PRIVATE
            ///      Received an encrypted message but cannot read
            ///      it because no private connection is established yet.
            /// - OTRL_MSGEVENT_RCVDMSG_UNREADABLE
            ///      Cannot read the received message.
            /// - OTRL_MSGEVENT_RCVDMSG_MALFORMED
            ///      The message received contains malformed data.
            /// - OTRL_MSGEVENT_LOG_HEARTBEAT_RCVD
            ///      Received a heartbeat.
            /// - OTRL_MSGEVENT_LOG_HEARTBEAT_SENT
            ///      Sent a heartbeat.
            /// - OTRL_MSGEVENT_RCVDMSG_GENERAL_ERR
            ///      Received a general OTR error. The argument 'message' will
            ///      also be passed and it will contain the OTR error message.
            /// - OTRL_MSGEVENT_RCVDMSG_UNENCRYPTED
            ///      Received an unencrypted message. The argument 'message' will
            ///      also be passed and it will contain the plaintext message.
            /// - OTRL_MSGEVENT_RCVDMSG_UNRECOGNIZED
            ///      Cannot recognize the type of OTR message received.
            /// - OTRL_MSGEVENT_RCVDMSG_FOR_OTHER_INSTANCE
            ///      Received and discarded a message intended for another instance. */
            /// </summary>
            IntPtr HandleMessageEvent;

            //void (*create_instag)(void *opdata, const char *accountname, const char *protocol);
            /// <summary>
            /// Create a instance tag for the given accountname/protocol if
            /// desired.
            /// </summary>
            IntPtr CreateInstanceTag;

            //void (*convert_msg)(void *opdata, ConnContext *context, OtrlConvertType convert_type, char ** dest, const char *src);
            /// <summary>
            /// Called immediately before a data message is encrypted, and after a data
            /// message is decrypted. The OtrlConvertType parameter has the value
            /// OTRL_CONVERT_SENDING or OTRL_CONVERT_RECEIVING to differentiate these
            /// cases.
            /// </summary>
            IntPtr ConvertMessage;

            //void (*convert_free)(void *opdata, ConnContext *context, char *dest);
            /// <summary>
            /// Deallocate a string returned by convert_msg. */
            /// </summary>
            IntPtr ConvertMessageFree;

            /// <summary>
            /// When timer_control is called, turn off any existing periodic
            /// timer.
            /// 
            /// Additionally, if interval > 0, set a new periodic timer
            /// to go off every interval seconds.  When that timer fires, you
            /// must call otrl_message_poll(userstate, uiops, uiopdata); from the
            /// main libotr thread.
            /// 
            /// The timing does not have to be exact; this timer is used to
            /// provide forward secrecy by cleaning up stale private state that
            /// may otherwise stick around in memory.  Note that the
            /// timer_control callback may be invoked from otrl_message_poll
            /// itself, possibly to indicate that interval == 0 (that is, that
            /// there's no more periodic work to be done at this time).
            /// 
            /// If you set this callback to NULL, then you must ensure that your
            /// application calls otrl_message_poll(userstate, uiops, uiopdata);
            ///  from the main libotr thread every definterval seconds (where
            /// definterval can be obtained by calling
            /// definterval = otrl_message_poll_get_default_interval(userstate);
            /// right after creating the userstate).  The advantage of
            /// implementing the timer_control callback is that the timer can be
            /// turned on by libotr only when it's needed.
            /// 
            /// It is not a problem (except for a minor performance hit) to call
            /// otrl_message_poll more often than requested, whether
            /// timer_control is implemented or not.
            /// 
            /// If you fail to implement the timer_control callback, and also
            /// fail to periodically call otrl_message_poll, then you open your
            /// users to a possible forward secrecy violation: an attacker that
            /// compromises the user's computer may be able to decrypt a handful
            /// of long-past messages (the first messages of an OTR
            /// conversation).
            /// </summary>
            //void (*timer_control)(void *opdata, unsigned int interval);
            IntPtr TimerControl;
        }

        public struct OtrlTLV
        {
            //unsigned short type;
            ushort Type;
            //unsigned short len;
            ushort Length;
            //unsigned char *data;
            IntPtr Data;
            //struct s_OtrlTLV *next;
            IntPtr Next;
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
        /*
        [DllImport("libotr.so.5")]
        public static extern int otrl_message_receiving(
            IntPtr userState, IntPtr messageAppOps, IntPtr opData,
            string accountName, string protocol, string sender, string message,
            );
        */

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
	}
}
