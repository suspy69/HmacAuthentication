using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Caching.Memory;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using System.IO;
using System.Security.Cryptography;

namespace Microsoft.AspNetCore.Authentication.HmacAuthentication
{
    public class HmacHandler : AuthenticationHandler<HmacOptions>
    {
        private readonly IMemoryCache _memoryCache;

        public HmacHandler(IOptionsMonitor<HmacOptions> options, ILoggerFactory logger, UrlEncoder encoder, IMemoryCache memoryCache, ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
            _memoryCache = memoryCache;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            try
            {
                string authorization = Request.Headers["authorization"];
                if (string.IsNullOrEmpty(authorization))
                {
                    return AuthenticateResult.NoResult();
                }
                bool valid = Validate(Request);

                if (valid)
                {
                    ClaimsPrincipal principal = new ClaimsPrincipal(new ClaimsIdentity("HMAC"));
                    AuthenticationTicket ticket = new AuthenticationTicket(principal, new AuthenticationProperties(), Options.AuthenticationScheme);
                    return AuthenticateResult.Success(ticket);
                }

                return AuthenticateResult.Fail("Authentication failed");
            }
            catch (Exception ex)
            {
                Logger.ErrorProcessingMessage(ex);

                throw;
            }
        }

        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            AuthenticateResult authResult = await HandleAuthenticateOnceSafeAsync();
            HmacChallengeContext eventContext = new HmacChallengeContext(Context, Scheme, Options, properties)
            {
                AuthenticationFailure = authResult?.Failure
            };

            if (Options.IncludeErrorDetails && eventContext.AuthenticationFailure != null)
            {
                eventContext.Error = "invalid_key";
                eventContext.ErrorDescription = CreateErrorDescription(eventContext.AuthenticationFailure);
            }

            Response.StatusCode = 401;

            if (string.IsNullOrEmpty(eventContext.Error) &&
                string.IsNullOrEmpty(eventContext.ErrorDescription) &&
                string.IsNullOrEmpty(eventContext.ErrorUri))
            {
                Response.Headers.Append(Microsoft.Net.Http.Headers.HeaderNames.WWWAuthenticate, Options.Challenge);
            }
            else
            {
                StringBuilder builder = new StringBuilder(Options.Challenge);
                if (Options.Challenge.IndexOf(" ", StringComparison.Ordinal) > 0)
                {
                    builder.Append(",");
                }
                if (!string.IsNullOrEmpty(eventContext.Error))
                {
                    builder.Append(" error=\"");
                    builder.Append(eventContext.Error);
                    builder.Append("\"");
                }
                if (!string.IsNullOrEmpty(eventContext.ErrorDescription))
                {
                    if (!string.IsNullOrEmpty(eventContext.Error))
                    {
                        builder.Append(",");
                    }

                    builder.Append(" error_description=\"");
                    builder.Append(eventContext.ErrorDescription);
                    builder.Append("\"");
                }
                if (!string.IsNullOrEmpty(eventContext.ErrorUri))
                {
                    if (!string.IsNullOrEmpty(eventContext.Error) ||
                        !string.IsNullOrEmpty(eventContext.ErrorDescription))
                    {
                        builder.Append(",");
                    }

                    builder.Append(" error_uri=\"");
                    builder.Append(eventContext.ErrorUri);
                    builder.Append("\"");
                }

                Response.Headers.Append(Microsoft.Net.Http.Headers.HeaderNames.WWWAuthenticate, builder.ToString());
            }
        }

        private static string CreateErrorDescription(Exception authFailure)
        {
            IEnumerable<Exception> exceptions;
            if (authFailure is AggregateException)
            {
                AggregateException agEx = authFailure as AggregateException;
                exceptions = agEx.InnerExceptions;
            }
            else
            {
                exceptions = new[] { authFailure };
            }

            List<string> messages = new List<string>();

            foreach (Exception ex in exceptions)
            {

            }

            return string.Join("; ", messages);
        }


        private bool Validate(HttpRequest request)
        {
            string header = request.Headers["authorization"];
            AuthenticationHeaderValue authenticationHeader = AuthenticationHeaderValue.Parse(header);
            if (Options.AuthenticationScheme.Equals(authenticationHeader.Scheme, StringComparison.OrdinalIgnoreCase))
            {
                string rawAuthenticationHeader = authenticationHeader.Parameter;
                string[] authenticationHeaderArray = GetAuthenticationValues(rawAuthenticationHeader);

                if (authenticationHeaderArray != null)
                {
                    string AppId = authenticationHeaderArray[0];
                    string incomingBase64Signature = authenticationHeaderArray[1];
                    string nonce = authenticationHeaderArray[2];
                    string requestTimeStamp = authenticationHeaderArray[3];

                    return IsValidRequest(request, AppId, incomingBase64Signature, nonce, requestTimeStamp);
                }
            }

            return false;
        }

        private bool IsValidRequest(HttpRequest req, string AppId, string incomingBase64Signature, string nonce, string requestTimeStamp)
        {
            string requestContentBase64String = "";
            string absoluteUri = string.Concat(
                req.Scheme,
                "://",
                req.Host.ToUriComponent(),
                req.PathBase.ToUriComponent(),
                req.Path.ToUriComponent(),
                req.QueryString.ToUriComponent());
            string requestUri = WebUtility.UrlEncode(absoluteUri).ToLower();
            string requestHttpMethod = req.Method;

            string authKey = Options.AuthKeys.GetValueOrDefault(AppId);

            if (string.IsNullOrEmpty(authKey))
            {
                return false;
            }

            string sharedKey = authKey;

            if (IsReplayRequest(nonce, requestTimeStamp))
            {
                return false;
            }

            byte[] hash = ComputeHash(req.Body);

            if (hash != null)
            {
                requestContentBase64String = Convert.ToBase64String(hash);
            }

            string data = String.Format("{0}{1}{2}{3}{4}{5}",
                AppId,
                requestHttpMethod,
                requestUri,
                requestTimeStamp,
                nonce,
                requestContentBase64String);

            byte[] secretKeyBytes = Convert.FromBase64String(sharedKey);

            byte[] signature = Encoding.UTF8.GetBytes(data);

            HMACSHA256 hmac = new HMACSHA256(secretKeyBytes);
            byte[] signatureBytes = hmac.ComputeHash(signature);
            hmac.Dispose();

            return (incomingBase64Signature.Equals(Convert.ToBase64String(signatureBytes), StringComparison.Ordinal));
        }

        private string[] GetAuthenticationValues(string rawAuthenticationHeader)
        {
            string[] credArray = rawAuthenticationHeader.Split(':');

            if (credArray.Length == 4)
            {
                return credArray;
            }
            else
            {
                return null;
            }
        }

        private bool IsReplayRequest(string nonce, string requestTimeStamp)
        {
            object nonceInMemory = _memoryCache.Get(nonce);
            if (nonceInMemory != null)
            {
                return true;
            }

            DateTime epochStart = new DateTime(1970, 01, 01, 0, 0, 0, 0, DateTimeKind.Utc);
            TimeSpan currentTs = DateTime.UtcNow - epochStart;

            Int64 serverTotalSeconds = Convert.ToInt64(currentTs.TotalSeconds);
            Int64 requestTotalSeconds = Convert.ToInt64(requestTimeStamp);
            decimal diff = Math.Abs(serverTotalSeconds - requestTotalSeconds);

            if (diff > Options.MaxRequestAgeInSeconds)
            {
                return true;
            }
            _memoryCache.Set(nonce, requestTimeStamp, DateTimeOffset.UtcNow.AddSeconds(Options.MaxRequestAgeInSeconds));
            return false;
        }

        private byte[] ComputeHash(Stream body)
        {
            MD5 md5 = MD5.Create();

            byte[] hash = null;
            byte[] content = ReadFully(body);
            if (content.Length != 0)
            {
                hash = md5.ComputeHash(content);
            }

            md5.Dispose();

            return hash;
        }

        private byte[] ReadFully(Stream input)
        {
            byte[] content;
            byte[] buffer = new byte[16 * 1024];
            MemoryStream ms = new MemoryStream();

            int read;
            while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
            {
                ms.Write(buffer, 0, read);
            }

            content = ms.ToArray();
            ms.Close();
            ms.Dispose();

            return content;
        }
    }
}
