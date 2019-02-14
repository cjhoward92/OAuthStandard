using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Text;

namespace OAuth
{
    /// <summary>A request wrapper for the OAuth 1.0a specification.</summary>
    /// <seealso href="http://oauth.net/" />
    public class OAuthRequest
    {
        public virtual OAuthSignatureMethod SignatureMethod { get; set; }

        public virtual OAuthSignatureTreatment SignatureTreatment { get; set; }

        public virtual OAuthRequestType Type { get; set; }

        public virtual string Method { get; set; }

        public virtual string Realm { get; set; }

        public virtual string ConsumerKey { get; set; }

        public virtual string ConsumerSecret { get; set; }

        public virtual string Token { get; set; }

        public virtual string TokenSecret { get; set; }

        public virtual string Verifier { get; set; }

        public virtual string ClientUsername { get; set; }

        public virtual string ClientPassword { get; set; }

        public virtual string CallbackUrl { get; set; }

        public virtual string Version { get; set; }

        public virtual string SessionHandle { get; set; }

        /// <seealso cref="!:http://oauth.net/core/1.0#request_urls" />
        public virtual string RequestUrl { get; set; }

        public string GetAuthorizationHeader(NameValueCollection parameters)
        {
            return this.GetAuthorizationHeader(new WebParameterCollection(parameters));
        }

        public string GetAuthorizationHeader(IDictionary<string, string> parameters)
        {
            return this.GetAuthorizationHeader(new WebParameterCollection(parameters));
        }

        public string GetAuthorizationHeader()
        {
            return this.GetAuthorizationHeader(new WebParameterCollection(0));
        }

        public string GetAuthorizationHeader(WebParameterCollection parameters)
        {
            switch (this.Type)
            {
                case OAuthRequestType.RequestToken:
                    this.ValidateRequestState();
                    return this.GetSignatureAuthorizationHeader(parameters);
                case OAuthRequestType.AccessToken:
                    this.ValidateAccessRequestState();
                    return this.GetSignatureAuthorizationHeader(parameters);
                case OAuthRequestType.ProtectedResource:
                    this.ValidateProtectedResourceState();
                    return this.GetSignatureAuthorizationHeader(parameters);
                case OAuthRequestType.ClientAuthentication:
                    this.ValidateClientAuthAccessRequestState();
                    return this.GetClientSignatureAuthorizationHeader(parameters);
                default:
                    throw new ArgumentOutOfRangeException();
            }
        }

        private string GetSignatureAuthorizationHeader(WebParameterCollection parameters)
        {
            string newSignature = this.GetNewSignature(parameters);
            parameters.Add("oauth_signature", newSignature);
            return this.WriteAuthorizationHeader(parameters);
        }

        private string GetClientSignatureAuthorizationHeader(WebParameterCollection parameters)
        {
            string newSignatureXauth = this.GetNewSignatureXAuth(parameters);
            parameters.Add("oauth_signature", newSignatureXauth);
            return this.WriteAuthorizationHeader(parameters);
        }

        private string WriteAuthorizationHeader(WebParameterCollection parameters)
        {
            StringBuilder stringBuilder = new StringBuilder("OAuth ");
            if (!OAuthRequest.IsNullOrBlank(this.Realm))
                stringBuilder.AppendFormat("realm=\"{0}\",", (object)OAuthTools.UrlEncodeRelaxed(this.Realm));
            parameters.Sort((Comparison<WebParameter>)((l, r) => l.Name.CompareTo(r.Name)));
            int num = 0;
            foreach (WebParameter webParameter in parameters.Where<WebParameter>((Func<WebParameter, bool>)(parameter =>
            {
                if (!OAuthRequest.IsNullOrBlank(parameter.Name) && !OAuthRequest.IsNullOrBlank(parameter.Value))
                    return parameter.Name.StartsWith("oauth_");
                return false;
            })))
            {
                ++num;
                string format = num < parameters.Count ? "{0}=\"{1}\"," : "{0}=\"{1}\"";
                stringBuilder.AppendFormat(format, (object)webParameter.Name, (object)webParameter.Value);
            }
            return stringBuilder.ToString();
        }

        public string GetAuthorizationQuery(NameValueCollection parameters)
        {
            return this.GetAuthorizationQuery(new WebParameterCollection(parameters));
        }

        public string GetAuthorizationQuery(IDictionary<string, string> parameters)
        {
            return this.GetAuthorizationQuery(new WebParameterCollection(parameters));
        }

        public string GetAuthorizationQuery()
        {
            return this.GetAuthorizationQuery(new WebParameterCollection(0));
        }

        private string GetAuthorizationQuery(WebParameterCollection parameters)
        {
            switch (this.Type)
            {
                case OAuthRequestType.RequestToken:
                    this.ValidateRequestState();
                    return this.GetSignatureAuthorizationQuery(parameters);
                case OAuthRequestType.AccessToken:
                    this.ValidateAccessRequestState();
                    return this.GetSignatureAuthorizationQuery(parameters);
                case OAuthRequestType.ProtectedResource:
                    this.ValidateProtectedResourceState();
                    return this.GetSignatureAuthorizationQuery(parameters);
                case OAuthRequestType.ClientAuthentication:
                    this.ValidateClientAuthAccessRequestState();
                    return this.GetClientSignatureAuthorizationQuery(parameters);
                default:
                    throw new ArgumentOutOfRangeException();
            }
        }

        private string GetSignatureAuthorizationQuery(WebParameterCollection parameters)
        {
            string newSignature = this.GetNewSignature(parameters);
            parameters.Add("oauth_signature", newSignature);
            return OAuthRequest.WriteAuthorizationQuery(parameters);
        }

        private string GetClientSignatureAuthorizationQuery(WebParameterCollection parameters)
        {
            string newSignatureXauth = this.GetNewSignatureXAuth(parameters);
            parameters.Add("oauth_signature", newSignatureXauth);
            return OAuthRequest.WriteAuthorizationQuery(parameters);
        }

        private static string WriteAuthorizationQuery(WebParameterCollection parameters)
        {
            StringBuilder stringBuilder = new StringBuilder();
            parameters.Sort((Comparison<WebParameter>)((l, r) => l.Name.CompareTo(r.Name)));
            int num = 0;
            foreach (WebParameter webParameter in parameters.Where<WebParameter>((Func<WebParameter, bool>)(parameter =>
            {
                if (!OAuthRequest.IsNullOrBlank(parameter.Name) && !OAuthRequest.IsNullOrBlank(parameter.Value))
                    return parameter.Name.StartsWith("oauth_");
                return false;
            })))
            {
                ++num;
                string format = num < parameters.Count ? "{0}={1}&" : "{0}={1}";
                stringBuilder.AppendFormat(format, (object)webParameter.Name, (object)webParameter.Value);
            }
            return stringBuilder.ToString();
        }

        private string GetNewSignature(WebParameterCollection parameters)
        {
            string timestamp = OAuthTools.GetTimestamp();
            string nonce = OAuthTools.GetNonce();
            this.AddAuthParameters((ICollection<WebParameter>)parameters, timestamp, nonce);
            return OAuthTools.GetSignature(this.SignatureMethod, this.SignatureTreatment, OAuthTools.ConcatenateRequestElements(this.Method.ToUpperInvariant(), this.RequestUrl, parameters), this.ConsumerSecret, this.TokenSecret);
        }

        private string GetNewSignatureXAuth(WebParameterCollection parameters)
        {
            string timestamp = OAuthTools.GetTimestamp();
            string nonce = OAuthTools.GetNonce();
            this.AddXAuthParameters((ICollection<WebParameter>)parameters, timestamp, nonce);
            return OAuthTools.GetSignature(this.SignatureMethod, this.SignatureTreatment, OAuthTools.ConcatenateRequestElements(this.Method.ToUpperInvariant(), this.RequestUrl, parameters), this.ConsumerSecret, this.TokenSecret);
        }

        public static OAuthRequest ForRequestToken(
          string consumerKey,
          string consumerSecret)
        {
            return new OAuthRequest()
            {
                Method = "GET",
                Type = OAuthRequestType.RequestToken,
                SignatureMethod = OAuthSignatureMethod.HmacSha1,
                SignatureTreatment = OAuthSignatureTreatment.Escaped,
                ConsumerKey = consumerKey,
                ConsumerSecret = consumerSecret
            };
        }

        public static OAuthRequest ForRequestToken(
          string consumerKey,
          string consumerSecret,
          string callbackUrl)
        {
            OAuthRequest oauthRequest = OAuthRequest.ForRequestToken(consumerKey, consumerSecret);
            oauthRequest.CallbackUrl = callbackUrl;
            return oauthRequest;
        }

        public static OAuthRequest ForAccessToken(
          string consumerKey,
          string consumerSecret,
          string requestToken,
          string requestTokenSecret)
        {
            return new OAuthRequest()
            {
                Method = "GET",
                Type = OAuthRequestType.AccessToken,
                SignatureMethod = OAuthSignatureMethod.HmacSha1,
                SignatureTreatment = OAuthSignatureTreatment.Escaped,
                ConsumerKey = consumerKey,
                ConsumerSecret = consumerSecret,
                Token = requestToken,
                TokenSecret = requestTokenSecret
            };
        }

        public static OAuthRequest ForAccessToken(
          string consumerKey,
          string consumerSecret,
          string requestToken,
          string requestTokenSecret,
          string verifier)
        {
            OAuthRequest oauthRequest = OAuthRequest.ForAccessToken(consumerKey, consumerSecret, requestToken, requestTokenSecret);
            oauthRequest.Verifier = verifier;
            return oauthRequest;
        }

        public static OAuthRequest ForAccessTokenRefresh(
          string consumerKey,
          string consumerSecret,
          string accessToken,
          string accessTokenSecret,
          string sessionHandle)
        {
            OAuthRequest oauthRequest = OAuthRequest.ForAccessToken(consumerKey, consumerSecret, accessToken, accessTokenSecret);
            oauthRequest.SessionHandle = sessionHandle;
            return oauthRequest;
        }

        public static OAuthRequest ForAccessTokenRefresh(
          string consumerKey,
          string consumerSecret,
          string accessToken,
          string accessTokenSecret,
          string sessionHandle,
          string verifier)
        {
            OAuthRequest oauthRequest = OAuthRequest.ForAccessToken(consumerKey, consumerSecret, accessToken, accessTokenSecret);
            oauthRequest.SessionHandle = sessionHandle;
            oauthRequest.Verifier = verifier;
            return oauthRequest;
        }

        public static OAuthRequest ForClientAuthentication(
          string consumerKey,
          string consumerSecret,
          string username,
          string password)
        {
            return new OAuthRequest()
            {
                Method = "GET",
                Type = OAuthRequestType.ClientAuthentication,
                SignatureMethod = OAuthSignatureMethod.HmacSha1,
                SignatureTreatment = OAuthSignatureTreatment.Escaped,
                ConsumerKey = consumerKey,
                ConsumerSecret = consumerSecret,
                ClientUsername = username,
                ClientPassword = password
            };
        }

        public static OAuthRequest ForProtectedResource(
          string method,
          string consumerKey,
          string consumerSecret,
          string accessToken,
          string accessTokenSecret)
        {
            return new OAuthRequest()
            {
                Method = "GET",
                Type = OAuthRequestType.ProtectedResource,
                SignatureMethod = OAuthSignatureMethod.HmacSha1,
                SignatureTreatment = OAuthSignatureTreatment.Escaped,
                ConsumerKey = consumerKey,
                ConsumerSecret = consumerSecret,
                Token = accessToken,
                TokenSecret = accessTokenSecret
            };
        }

        private void ValidateRequestState()
        {
            if (OAuthRequest.IsNullOrBlank(this.Method))
                throw new ArgumentException("You must specify an HTTP method");
            if (OAuthRequest.IsNullOrBlank(this.RequestUrl))
                throw new ArgumentException("You must specify a request token URL");
            if (OAuthRequest.IsNullOrBlank(this.ConsumerKey))
                throw new ArgumentException("You must specify a consumer key");
            if (OAuthRequest.IsNullOrBlank(this.ConsumerSecret))
                throw new ArgumentException("You must specify a consumer secret");
        }

        private void ValidateAccessRequestState()
        {
            if (OAuthRequest.IsNullOrBlank(this.Method))
                throw new ArgumentException("You must specify an HTTP method");
            if (OAuthRequest.IsNullOrBlank(this.RequestUrl))
                throw new ArgumentException("You must specify an access token URL");
            if (OAuthRequest.IsNullOrBlank(this.ConsumerKey))
                throw new ArgumentException("You must specify a consumer key");
            if (OAuthRequest.IsNullOrBlank(this.ConsumerSecret))
                throw new ArgumentException("You must specify a consumer secret");
            if (OAuthRequest.IsNullOrBlank(this.Token))
                throw new ArgumentException("You must specify a token");
        }

        private void ValidateClientAuthAccessRequestState()
        {
            if (OAuthRequest.IsNullOrBlank(this.Method))
                throw new ArgumentException("You must specify an HTTP method");
            if (OAuthRequest.IsNullOrBlank(this.RequestUrl))
                throw new ArgumentException("You must specify an access token URL");
            if (OAuthRequest.IsNullOrBlank(this.ConsumerKey))
                throw new ArgumentException("You must specify a consumer key");
            if (OAuthRequest.IsNullOrBlank(this.ConsumerSecret))
                throw new ArgumentException("You must specify a consumer secret");
            if (OAuthRequest.IsNullOrBlank(this.ClientUsername) || OAuthRequest.IsNullOrBlank(this.ClientPassword))
                throw new ArgumentException("You must specify user credentials");
        }

        private void ValidateProtectedResourceState()
        {
            if (OAuthRequest.IsNullOrBlank(this.Method))
                throw new ArgumentException("You must specify an HTTP method");
            if (OAuthRequest.IsNullOrBlank(this.ConsumerKey))
                throw new ArgumentException("You must specify a consumer key");
            if (OAuthRequest.IsNullOrBlank(this.ConsumerSecret))
                throw new ArgumentException("You must specify a consumer secret");
        }

        private void AddAuthParameters(
          ICollection<WebParameter> parameters,
          string timestamp,
          string nonce)
        {
            WebParameterCollection parameterCollection = new WebParameterCollection()
      {
        new WebParameter("oauth_consumer_key", this.ConsumerKey),
        new WebParameter("oauth_nonce", nonce),
        new WebParameter("oauth_signature_method", OAuthRequest.ToRequestValue(this.SignatureMethod)),
        new WebParameter("oauth_timestamp", timestamp),
        new WebParameter("oauth_version", this.Version ?? "1.0")
      };
            if (!OAuthRequest.IsNullOrBlank(this.Token))
                parameterCollection.Add(new WebParameter("oauth_token", this.Token));
            if (!OAuthRequest.IsNullOrBlank(this.CallbackUrl))
                parameterCollection.Add(new WebParameter("oauth_callback", this.CallbackUrl));
            if (!OAuthRequest.IsNullOrBlank(this.Verifier))
                parameterCollection.Add(new WebParameter("oauth_verifier", this.Verifier));
            if (!OAuthRequest.IsNullOrBlank(this.SessionHandle))
                parameterCollection.Add(new WebParameter("oauth_session_handle", this.SessionHandle));
            foreach (WebParameter webParameter in parameterCollection)
                parameters.Add(webParameter);
        }

        private void AddXAuthParameters(
          ICollection<WebParameter> parameters,
          string timestamp,
          string nonce)
        {
            foreach (WebParameter webParameter in new WebParameterCollection()
      {
        new WebParameter("x_auth_username", this.ClientUsername),
        new WebParameter("x_auth_password", this.ClientPassword),
        new WebParameter("x_auth_mode", "client_auth"),
        new WebParameter("oauth_consumer_key", this.ConsumerKey),
        new WebParameter("oauth_signature_method", OAuthRequest.ToRequestValue(this.SignatureMethod)),
        new WebParameter("oauth_timestamp", timestamp),
        new WebParameter("oauth_nonce", nonce),
        new WebParameter("oauth_version", this.Version ?? "1.0")
      })
                parameters.Add(webParameter);
        }

        public static string ToRequestValue(OAuthSignatureMethod signatureMethod)
        {
            string upper = signatureMethod.ToString().ToUpper();
            int startIndex = upper.IndexOf("SHA1");
            if (startIndex <= -1)
                return upper;
            return upper.Insert(startIndex, "-");
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
