using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.HmacAuthentication;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class HmacExtensions
    {
        public static AuthenticationBuilder AddHmacAuthentication(this AuthenticationBuilder builder)
            => builder.AddHmacAuthentication(HmacDefaults.AuthenticationScheme, _ => { });

        public static AuthenticationBuilder AddHmacAuthentication(this AuthenticationBuilder builder, Action<HmacOptions> configureOptions)
            => builder.AddHmacAuthentication(HmacDefaults.AuthenticationScheme, configureOptions);

        public static AuthenticationBuilder AddHmacAuthentication(this AuthenticationBuilder builder, string authenticationScheme, Action<HmacOptions> configureOptions)
            => builder.AddHmacAuthentication(authenticationScheme, displayName: null, configureOptions: configureOptions);

        public static AuthenticationBuilder AddHmacAuthentication(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<HmacOptions> configureOptions)
        {
            return builder.AddScheme<HmacOptions, HmacHandler>(authenticationScheme, displayName, configureOptions);
        }
    }
}
