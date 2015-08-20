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

namespace Otr
{
	public class UserState : IDisposable
	{
		public IntPtr Handle { get; set; }

		public UserState()
		{
			Handle = OtrApi.otrl_userstate_create();
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
	}
}
