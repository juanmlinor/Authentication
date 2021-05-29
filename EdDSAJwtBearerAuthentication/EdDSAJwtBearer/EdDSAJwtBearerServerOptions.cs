using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EdDSAJwtBearer
{
   public class EdDSAJwtBearerServerOptions
    {
        public string Audience { get; set; }

        public string Issuer { get; set; }

        public string PrivateSigninKey { get; set; }

        public string PublicSigninKey { get; set; }

      

}
}
