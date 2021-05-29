using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EdDSAJwtBearer
{
    class EdDSAJwtBearerErrors
    {
        public const string ValidIssuerRequiered ="ValidIssuer is required when Validatelssuer is true";
        public const string ValidAudienceRequiered = "ValidAudience is required when ValidateAudience is true";

        public const string InvalidToken =   "(001) Invalid Bearer authentication token";
        public const string InvalidIssuer =   "(002) Invalid Issuer";
        public const string InvalidAudience = "(003) Invalid Audience";
        public const string ExpiredToken =  "(004) Token has expired";
    }
}