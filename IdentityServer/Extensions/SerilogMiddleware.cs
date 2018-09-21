using Microsoft.AspNetCore.Http;
using Serilog.Context;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServer.Extensions
{
    public class SerilogMiddleware
    {
        private readonly RequestDelegate next;

        public SerilogMiddleware(RequestDelegate next)
        {
            this.next = next;
        }

        public Task Invoke(HttpContext context)
        {
            LogContext.PushProperty("UserName", context.User.Identity.Name);
            LogContext.PushProperty("IPAddress", context.Connection.RemoteIpAddress);
            return next(context);
        }
    }
}
