using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace OAuth
{
    /// <summary>
    /// A general purpose toolset for creating components of an OAuth request.
    ///  </summary>
    /// <seealso href="http://oauth.net/" />
    public static class OAuthTools
    {
        private static readonly object _randomLock = new object();
        private static readonly RandomNumberGenerator _rng = RandomNumberGenerator.Create();
        /// <summary>
        /// All text parameters are UTF-8 encoded (per section 5.1).
        /// </summary>
        /// <seealso href="http://www.hueniverse.com/hueniverse/2008/10/beginners-gui-1.html" />
        private static readonly Encoding _encoding = Encoding.UTF8;
        private const string AlphaNumeric = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";
        private const string Digit = "1234567890";
        private const string Lower = "abcdefghijklmnopqrstuvwxyz";
        private const string Unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890-._~";
        private const string Upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        private static readonly Random _random;

        static OAuthTools()
        {
            byte[] data = new byte[4];
            OAuthTools._rng.GetNonZeroBytes(data);
            OAuthTools._random = new Random(BitConverter.ToInt32(data, 0));
        }

        /// <summary>
        /// Generates a random 16-byte lowercase alphanumeric string.
        /// </summary>
        /// <seealso href="http://oauth.net/core/1.0#nonce" />
        /// <returns></returns>
        public static string GetNonce()
        {
            char[] chArray = new char[16];
            lock (OAuthTools._randomLock)
            {
                for (int index = 0; index < chArray.Length; ++index)
                    chArray[index] = "abcdefghijklmnopqrstuvwxyz1234567890"[OAuthTools._random.Next(0, "abcdefghijklmnopqrstuvwxyz1234567890".Length)];
            }
            return new string(chArray);
        }

        /// <summary>
        /// Generates a timestamp based on the current elapsed seconds since '01/01/1970 0000 GMT"
        /// </summary>
        /// <seealso href="http://oauth.net/core/1.0#nonce" />
        /// <returns></returns>
        public static string GetTimestamp()
        {
            return OAuthTools.GetTimestamp(DateTime.UtcNow);
        }

        /// <summary>
        /// Generates a timestamp based on the elapsed seconds of a given time since '01/01/1970 0000 GMT"
        /// </summary>
        /// <seealso href="http://oauth.net/core/1.0#nonce" />
        /// <param name="dateTime">A specified point in time.</param>
        /// <returns></returns>
        public static string GetTimestamp(DateTime dateTime)
        {
            return OAuthTools.ToUnixTime(dateTime).ToString();
        }

        private static long ToUnixTime(DateTime dateTime)
        {
            return (long)(dateTime - new DateTime(1970, 1, 1)).TotalSeconds;
        }

        /// <summary>
        /// URL encodes a string based on section 5.1 of the OAuth spec.
        /// Namely, percent encoding with [RFC3986], avoiding unreserved characters,
        /// upper-casing hexadecimal characters, and UTF-8 encoding for text value pairs.
        /// </summary>
        /// <param name="value"></param>
        /// <seealso href="http://oauth.net/core/1.0#encoding_parameters" />
        public static string UrlEncodeRelaxed(string value)
        {
            return Uri.EscapeDataString(value).Replace("(", OAuthTools.PercentEncode("(")).Replace(")", OAuthTools.PercentEncode(")"));
        }

        private static string PercentEncode(string s)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(s);
            StringBuilder stringBuilder = new StringBuilder();
            foreach (byte num in bytes)
            {
                if (num > (byte)7 && num < (byte)11 || num == (byte)13)
                    stringBuilder.Append(string.Format("%0{0:X}", (object)num));
                else
                    stringBuilder.Append(string.Format("%{0:X}", (object)num));
            }
            return stringBuilder.ToString();
        }

        /// <summary>
        /// URL encodes a string based on section 5.1 of the OAuth spec.
        /// Namely, percent encoding with [RFC3986], avoiding unreserved characters,
        /// upper-casing hexadecimal characters, and UTF-8 encoding for text value pairs.
        /// </summary>
        /// <param name="value"></param>
        /// <seealso href="http://oauth.net/core/1.0#encoding_parameters" />
        public static string UrlEncodeStrict(string value)
        {
            return value.Where<char>((Func<char, bool>)(c =>
            {
                if (!"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890-._~".Contains<char>(c))
                    return c != '%';
                return false;
            })).Aggregate<char, string>(value, (Func<string, char, string>)((current, c) => current.Replace(c.ToString(), OAuthTools.PercentEncode(c.ToString())))).Replace("%%", "%25%");
        }

        /// <summary>
        /// Sorts a collection of key-value pairs by name, and then value if equal,
        /// concatenating them into a single string. This string should be encoded
        /// prior to, or after normalization is run.
        /// </summary>
        /// <seealso href="http://oauth.net/core/1.0#rfc.section.9.1.1" />
        /// <param name="parameters"></param>
        /// <returns></returns>
        public static string NormalizeRequestParameters(WebParameterCollection parameters)
        {
            return OAuthTools.Concatenate((ICollection<WebParameter>)OAuthTools.SortParametersExcludingSignature(parameters), "=", "&");
        }

        private static string Concatenate(
          ICollection<WebParameter> collection,
          string separator,
          string spacer)
        {
            StringBuilder stringBuilder = new StringBuilder();
            int count = collection.Count;
            int num = 0;
            foreach (WebParameter webParameter in (IEnumerable<WebParameter>)collection)
            {
                stringBuilder.Append(webParameter.Name);
                stringBuilder.Append(separator);
                stringBuilder.Append(webParameter.Value);
                ++num;
                if (num < count)
                    stringBuilder.Append(spacer);
            }
            return stringBuilder.ToString();
        }

        /// <summary>
        /// Sorts a <see cref="T:OAuth.WebParameterCollection" /> by name, and then value if equal.
        /// </summary>
        /// <param name="parameters">A collection of parameters to sort</param>
        /// <returns>A sorted parameter collection</returns>
        public static WebParameterCollection SortParametersExcludingSignature(
          WebParameterCollection parameters)
        {
            WebParameterCollection source = new WebParameterCollection((IEnumerable<WebParameter>)parameters);
            IEnumerable<WebParameter> parameters1 = source.Where<WebParameter>((Func<WebParameter, bool>)(n => OAuthTools.EqualsIgnoreCase(n.Name, "oauth_signature")));
            source.RemoveAll(parameters1);
            foreach (WebParameter webParameter in source)
                webParameter.Value = OAuthTools.UrlEncodeStrict(webParameter.Value);
            source.Sort((Comparison<WebParameter>)((x, y) =>
            {
                if (!x.Name.Equals(y.Name))
                    return x.Name.CompareTo(y.Name);
                return x.Value.CompareTo(y.Value);
            }));
            return source;
        }

        private static bool EqualsIgnoreCase(string left, string right)
        {
            return string.Compare(left, right, StringComparison.InvariantCultureIgnoreCase) == 0;
        }

        /// <summary>
        /// Creates a request URL suitable for making OAuth requests.
        /// Resulting URLs must exclude port 80 or port 443 when accompanied by HTTP and HTTPS, respectively.
        /// Resulting URLs must be lower case.
        /// </summary>
        /// <seealso href="http://oauth.net/core/1.0#rfc.section.9.1.2" />
        /// <param name="url">The original request URL</param>
        /// <returns></returns>
        public static string ConstructRequestUrl(Uri url)
        {
            if (url == (Uri)null)
                throw new ArgumentNullException(nameof(url));
            StringBuilder stringBuilder = new StringBuilder();
            string str1 = string.Format("{0}://{1}", (object)url.Scheme, (object)url.Host);
            string str2 = string.Format(":{0}", (object)url.Port);
            bool flag1 = url.Scheme == "http" && url.Port == 80;
            bool flag2 = url.Scheme == "https" && url.Port == 443;
            stringBuilder.Append(str1);
            stringBuilder.Append(flag1 || flag2 ? "" : str2);
            stringBuilder.Append(url.AbsolutePath);
            return stringBuilder.ToString();
        }

        /// <summary>
        /// Creates a request elements concatentation value to send with a request.
        /// This is also known as the signature base.
        /// </summary>
        /// <seealso href="http://oauth.net/core/1.0#rfc.section.9.1.3" />
        /// <seealso href="http://oauth.net/core/1.0#sig_base_example" />
        /// <param name="method">The request's HTTP method type</param>
        /// <param name="url">The request URL</param>
        /// <param name="parameters">The request's parameters</param>
        /// <returns>A signature base string</returns>
        public static string ConcatenateRequestElements(
          string method,
          string url,
          WebParameterCollection parameters)
        {
            StringBuilder stringBuilder = new StringBuilder();
            string str1 = method.ToUpper() + "&";
            string str2 = OAuthTools.UrlEncodeRelaxed(OAuthTools.ConstructRequestUrl(new Uri(url))) + "&";
            string str3 = OAuthTools.UrlEncodeRelaxed(OAuthTools.NormalizeRequestParameters(parameters));
            stringBuilder.Append(str1);
            stringBuilder.Append(str2);
            stringBuilder.Append(str3);
            return stringBuilder.ToString();
        }

        /// <summary>
        /// Creates a signature value given a signature base and the consumer secret.
        /// This method is used when the token secret is currently unknown.
        /// </summary>
        /// <seealso href="http://oauth.net/core/1.0#rfc.section.9.2" />
        /// <param name="signatureMethod">The hashing method</param>
        /// <param name="signatureBase">The signature base</param>
        /// <param name="consumerSecret">The consumer key</param>
        /// <returns></returns>
        public static string GetSignature(
          OAuthSignatureMethod signatureMethod,
          string signatureBase,
          string consumerSecret)
        {
            return OAuthTools.GetSignature(signatureMethod, OAuthSignatureTreatment.Escaped, signatureBase, consumerSecret, (string)null);
        }

        /// <summary>
        /// Creates a signature value given a signature base and the consumer secret.
        /// This method is used when the token secret is currently unknown.
        /// </summary>
        /// <seealso href="http://oauth.net/core/1.0#rfc.section.9.2" />
        /// <param name="signatureMethod">The hashing method</param>
        /// <param name="signatureTreatment">The treatment to use on a signature value</param>
        /// <param name="signatureBase">The signature base</param>
        /// <param name="consumerSecret">The consumer key</param>
        /// <returns></returns>
        public static string GetSignature(
          OAuthSignatureMethod signatureMethod,
          OAuthSignatureTreatment signatureTreatment,
          string signatureBase,
          string consumerSecret)
        {
            return OAuthTools.GetSignature(signatureMethod, signatureTreatment, signatureBase, consumerSecret, (string)null);
        }

        /// <summary>
        /// Creates a signature value given a signature base and the consumer secret and a known token secret.
        /// </summary>
        /// <seealso href="http://oauth.net/core/1.0#rfc.section.9.2" />
        /// <param name="signatureMethod">The hashing method</param>
        /// <param name="signatureBase">The signature base</param>
        /// <param name="consumerSecret">The consumer secret</param>
        /// <param name="tokenSecret">The token secret</param>
        /// <returns></returns>
        public static string GetSignature(
          OAuthSignatureMethod signatureMethod,
          string signatureBase,
          string consumerSecret,
          string tokenSecret)
        {
            return OAuthTools.GetSignature(signatureMethod, OAuthSignatureTreatment.Escaped, consumerSecret, tokenSecret);
        }

        /// <summary>
        /// Creates a signature value given a signature base and the consumer secret and a known token secret.
        /// </summary>
        /// <seealso href="http://oauth.net/core/1.0#rfc.section.9.2" />
        /// <param name="signatureMethod">The hashing method</param>
        /// <param name="signatureTreatment">The treatment to use on a signature value</param>
        /// <param name="signatureBase">The signature base</param>
        /// <param name="consumerSecret">The consumer secret</param>
        /// <param name="tokenSecret">The token secret</param>
        /// <returns></returns>
        public static string GetSignature(
          OAuthSignatureMethod signatureMethod,
          OAuthSignatureTreatment signatureTreatment,
          string signatureBase,
          string consumerSecret,
          string tokenSecret)
        {
            if (OAuthTools.IsNullOrBlank(tokenSecret))
                tokenSecret = string.Empty;
            consumerSecret = OAuthTools.UrlEncodeRelaxed(consumerSecret);
            tokenSecret = OAuthTools.UrlEncodeRelaxed(tokenSecret);
            if (signatureMethod != OAuthSignatureMethod.HmacSha1)
                throw new NotImplementedException("Only HMAC-SHA1 is currently supported.");
            HMACSHA1 hmacshA1 = new HMACSHA1();
            string s = consumerSecret + "&" + tokenSecret;
            hmacshA1.Key = OAuthTools._encoding.GetBytes(s);
            string str = OAuthTools.HashWith(signatureBase, (HashAlgorithm)hmacshA1);
            return signatureTreatment == OAuthSignatureTreatment.Escaped ? OAuthTools.UrlEncodeRelaxed(str) : str;
        }

        private static string HashWith(string input, HashAlgorithm algorithm)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(input);
            return Convert.ToBase64String(algorithm.ComputeHash(bytes));
        }

        private static bool IsNullOrBlank(string value)
        {
            if (string.IsNullOrEmpty(value))
                return true;
            if (!string.IsNullOrEmpty(value))
                return value.Trim() == string.Empty;
            return false;
        }
    }
}
