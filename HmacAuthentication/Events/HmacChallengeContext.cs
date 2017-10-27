using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Authentication.HmacAuthentication
{
    public class HmacChallengeContext : PropertiesContext<HmacOptions>
    {
        public HmacChallengeContext(
            HttpContext context,
            AuthenticationScheme scheme,
            HmacOptions options,
            AuthenticationProperties properties)
            : base(context, scheme, options, properties) { }

        public Exception AuthenticationFailure { get; set; }

        public string Error { get; set; }

        public string ErrorDescription { get; set; }

        public string ErrorUri { get; set; }

        public bool Handled { get; private set; }

        public void HandleResponse() => Handled = true;
    }
}
