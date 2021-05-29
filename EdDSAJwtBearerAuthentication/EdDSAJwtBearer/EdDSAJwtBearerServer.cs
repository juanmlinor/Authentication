﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace EdDSAJwtBearer
{
   public class EdDSAJwtBearerServer
    {
        public EdDSAJwtBearerServerOptions EdDSAJwtBearerServerOptions { get; set; }
        public EdDSAJwtBearerServer() { }
     public EdDSAJwtBearerServer(EdDSAJwtBearerServerOptions options)
        {
            EdDSAJwtBearerServerOptions = options;
        }
        public string CreateToken(IEnumerable<Claim> claims,
        string[] roles, DateTime expires) =>
        EdDSATokenHandler.CreateToken(EdDSAJwtBearerServerOptions.PrivateSigninKey,
        EdDSAJwtBearerServerOptions.Issuer,
        EdDSAJwtBearerServerOptions.Audience,
        claims, roles, expires);
    }
}
