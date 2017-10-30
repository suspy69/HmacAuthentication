using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authentication.HmacAuthentication
{
    public class HmacEvents
    {
        public Func<HmacChallengeContext, Task> OnChallenge { get; set; } = context => Task.CompletedTask;

        public virtual Task Challenge(HmacChallengeContext context) => OnChallenge(context);
    }
}
