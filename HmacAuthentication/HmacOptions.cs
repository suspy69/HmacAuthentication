using System;
using System.Collections.Generic;
using System.Text;
using System.Net.Http;
using Microsoft.AspNetCore.Authentication;

namespace Microsoft.AspNetCore.Authentication.HmacAuthentication
{
    public class HmacOptions : AuthenticationSchemeOptions
    {
        public ulong MaxRequestAgeInSeconds { get; set; } = 300;

        public Dictionary<string, string> AuthKeys { get; set; } = new Dictionary<string, string>();

        public string AuthenticationScheme { get; set; } = HmacDefaults.AuthenticationScheme;

        public string Challenge { get; set; } = HmacDefaults.AuthenticationScheme;

        public bool IncludeErrorDetails { get; set; } = true;
    }
}
