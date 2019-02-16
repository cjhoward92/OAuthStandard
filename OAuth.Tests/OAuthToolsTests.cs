using System;
using System.Threading;
using Xunit;

namespace OAuth.Tests
{
    public class OAuthToolsTests
    {
        private const int NonceLength = 16;

        [Fact]
        public void GetNonce_Creates_16_Byte_Nonce()
        {
            string nonce = OAuthTools.GetNonce();

            Assert.NotNull(nonce);
            Assert.NotEmpty(nonce);
            Assert.Equal(NonceLength, nonce.Length);
        }

        [Fact]
        public void GetNonce_Creates_New_Nonce_Each_Run()
        {
            string nonce1 = OAuthTools.GetNonce();
            string nonce2 = OAuthTools.GetNonce();
            string nonce3 = OAuthTools.GetNonce();

            Assert.NotNull(nonce1);
            Assert.NotNull(nonce2);
            Assert.NotNull(nonce3);

            Assert.NotEmpty(nonce1);
            Assert.NotEmpty(nonce2);
            Assert.NotEmpty(nonce3);

            Assert.NotEqual(nonce1, nonce2);
            Assert.NotEqual(nonce2, nonce3);
            Assert.NotEqual(nonce1, nonce3);
        }

        [Fact]
        public void GetNonce_Is_Threadsafe()
        {
            string nonce1 = string.Empty;
            string nonce2 = string.Empty;

            Thread thread1 = new Thread(() =>
            {
                Thread.Sleep(100);
                nonce1 = OAuthTools.GetNonce();
            });
            Thread thread2 = new Thread(() =>
            {
                Thread.Sleep(100);
                nonce2 = OAuthTools.GetNonce();
            });

            thread1.Start();
            thread2.Start();
            thread1.Join();
            thread2.Join();

            Assert.NotNull(nonce1);
            Assert.NotNull(nonce2);

            Assert.NotEmpty(nonce1);
            Assert.NotEmpty(nonce2);

            Assert.NotEqual(nonce1, nonce2);
        }

        [Fact]
        public void GetTimeStamp_Calculates_Seconds_From_Epoch()
        {
            int secondsFromEpoch = 1000;
            DateTime dateTimeFromEpoch = new DateTime(1970, 1, 1).AddSeconds(secondsFromEpoch);

            string unixTime = OAuthTools.GetTimestamp(dateTimeFromEpoch);

            Assert.NotNull(unixTime);
            Assert.NotEmpty(unixTime);
            Assert.Equal(secondsFromEpoch, Convert.ToInt32(unixTime));
        }

        [Fact]
        public void GetTimeStamp_Time_Before_Epoch_Is_Accurate()
        {
            DateTime earlyDateTime = new DateTime(1900, 1, 1);
            string unixTime = OAuthTools.GetTimestamp(earlyDateTime);

            Assert.NotNull(unixTime);
            Assert.NotEmpty(unixTime);
            Assert.Equal((earlyDateTime - new DateTime(1970, 1, 1)).TotalSeconds, Convert.ToInt64(unixTime));
        }

        [Theory]
        [InlineData("http://www.example.com/mywebsite?test= some word with spaces", "http%3A%2F%2Fwww.example.com%2Fmywebsite%3Ftest%3D%20some%20word%20with%20spaces")]
        [InlineData("()()()()()()()", "%28%29%28%29%28%29%28%29%28%29%28%29%28%29")]
        [InlineData("", "")]
        [InlineData("1234567890abcdefghijklmnopqrstuvwxyz-/+-_!@#$%^&*()", "1234567890abcdefghijklmnopqrstuvwxyz-%2F%2B-_%21%40%23%24%25%5E%26%2A%28%29")]
        public void UrlEncodeRelaxed_Encodes_Uri_Properly(string uri, string expected)
        {
            string encodedUri = OAuthTools.UrlEncodeRelaxed(uri);
            Assert.Equal(expected, encodedUri);
        }

        [Fact]
        public void UrlEncodeRelaxed_Throws_ArgumentNull_On_Null_String()
        {
            Assert.Throws<ArgumentNullException>(() => OAuthTools.UrlEncodeRelaxed(null));
        }

        [Theory]
        [InlineData("http://www.example.com/mywebsite?test= some word with spaces", "http%3A%2F%2Fwww.example.com%2Fmywebsite%3Ftest%3D%20some%20word%20with%20spaces")]
        [InlineData("()()()()()()()", "%28%29%28%29%28%29%28%29%28%29%28%29%28%29")]
        [InlineData("", "")]
        [InlineData("1234567890abcdefghijklmnopqrstuvwxyz-/+-_!@#$%^&*()", "1234567890abcdefghijklmnopqrstuvwxyz-%2F%2B-_%21%40%23%24%25%5E%26%2A%28%29")]
        public void UrlEncodeStrict_Encodes_Uri_Properly(string uri, string expected)
        {
            string encodedUri = OAuthTools.UrlEncodeStrict(uri);
            Assert.Equal(expected, encodedUri);
        }

        [Fact]
        public void UrlEncodeStrict_Throws_ArgumentNull_On_Null_String()
        {
            Assert.Throws<ArgumentNullException>(() => OAuthTools.UrlEncodeStrict(null));
        }

        [Fact]
        public void NormalizeRequestParameters_Normalizes_And_Encodes_QueryString()
        {
            var parameters = new WebParameterCollection(new[]
            {
                new WebParameter("test", "value"),
                new WebParameter("name", "joe"),
                new WebParameter("grant_type", "code"),
                new WebParameter("string", "this+is+a+string"),
            });
            var expected = "grant_type=code&name=joe&string=this%2Bis%2Ba%2Bstring&test=value";

            var result = OAuthTools.NormalizeRequestParameters(parameters);

            Assert.Equal(expected, result);
        }

        [Fact]
        public void NormalizeRequestParameters_Returns_Blank_On_Empty_Collection()
        {
            var result = OAuthTools.NormalizeRequestParameters(new WebParameterCollection());
            Assert.Equal(String.Empty, result);
        }

        [Fact]
        public void NormalizeRequestParameters_Throws_ArgumentNull_On_Null_Collection()
        {
            Assert.Throws<ArgumentNullException>(() => OAuthTools.NormalizeRequestParameters(null));
        }
    }
}
