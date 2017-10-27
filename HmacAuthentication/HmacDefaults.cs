using System;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Authentication.HmacAuthentication
{
    public static class HmacDefaults
    {
        public const string AuthenticationScheme = "Hmac";

        public const int MaxRequestAgeInSeconds = 300;
    }
}
