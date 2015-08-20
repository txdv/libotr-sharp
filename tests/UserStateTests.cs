using System;
using NUnit.Framework;

namespace Otr
{
    [TestFixture]
    public class UserStateTests
    {
        [Test]
        public void Ctor()
        {
            var us = new UserState();
            Assert.IsNotNull(us);
        }

        [Test]
        public void Dispose()
        {
            var us = new UserState();
            us.Dispose();
        }
    }
}
