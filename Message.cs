using System;
using System.Runtime.InteropServices;

namespace Otr
{
	public enum OtrlErrorCode {
		None,
		EncryptionError,
		MsgNotInPrivate,
		MsgUnreadable,
		MsgMalformed
	}

	public enum OtrlSmpEvent {
		None,
		Error,
		Abort,
		Cheated,
		AskForAnswer,
		AskForSecret,
		InProgress,
		Success,
		Failure
	}

	public static class MessageApi
	{

	}
}

