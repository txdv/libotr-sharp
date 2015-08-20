using System;
using NUnit.Framework;

namespace Otr
{
	[TestFixture]
	public class NativeTests
	{
        [Test]
        public void UserState()
        {
            var us = OtrApi.otrl_userstate_create();
            Assert.AreNotEqual(us, IntPtr.Zero);
            OtrApi.otrl_userstate_free(us);
        }
	}
}
