using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Authentication.HmacAuthentication
{
    public class AuthenticationFailedContext : ResultContext<HmacOptions>
    {
        public AuthenticationFailedContext(
            HttpContext context,
            AuthenticationScheme scheme,
            HmacOptions options)
            : base(context, scheme, options) { }

        public Exception Exception { get; set; }
    }
}
