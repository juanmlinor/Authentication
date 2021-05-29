using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;

namespace EdDSAJwtBearer
{
   public class EdDSAJwtBearerAuthenticationHandler : AuthenticationHandler<EdDSAJwtBearerOptions>
         {

      public EdDSAJwtBearerAuthenticationHandler(
            IOptionsMonitor<EdDSAJwtBearerOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock) : base(options, logger, encoder, clock) { }
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
            {
             AuthenticateResult Result = AuthenticateResult.NoResult();
            
            if (Request.Headers.ContainsKey("Authorization"))
            { 
              if (AuthenticationHeaderValue.TryParse(Request.Headers["Authorization"],
            out AuthenticationHeaderValue HeaderValue))
            { 
                if("Bearer".Equals(HeaderValue.Scheme, StringComparison.OrdinalIgnoreCase))
                    {
                  try { 
                        string Error;
                        string Token = HeaderValue.Parameter;

                if(TryGetPayloadWithTokenValidation(Token, Options,
                     out Dictionary<string, object> Payload, out Error))
                      {
                            List<Claim> Claims = Payload.Where(c => c.Key != "roles")
                               .Select(c => new Claim(c.Key, $"{c.Value}")).ToList();
                      if (Payload.TryGetValue("role", out object Roles))
                          { 
                           string[] RolesArray = JsonSerializer.
                            Deserialize<string[]> (Roles.ToString());
                          if (RolesArray != null)
                            {
                            foreach (var Role in RolesArray)
                             { 
                               Claims.Add(new Claim("role", Role.ToString()));
                            }
                        }
                    }

                      ClaimsIdentity Identity = new ClaimsIdentity(
                      Claims, Scheme.Name, "firstName", "role");

                     ClaimsPrincipal Principal = new ClaimsPrincipal(Identity);
                     AuthenticationTicket Ticket;

                    if (Options.SaveToken)
                            { 
                            //Almacenar el token en una instacia de
                            //ButhenticationProperties
                            var Properties = new AuthenticationProperties();
                                    Properties.StoreTokens(new AuthenticationToken[]
                                    {
                                        new AuthenticationToken
                                        {
                                            Name = "access_toke",
                                            Value = Token
                                        }
                                    });
                                    //crea ticke
                                    Ticket = new AuthenticationTicket(Principal, Properties, Scheme.Name);
                                }
                                else
                                {
                                    Ticket = new AuthenticationTicket(Principal, Scheme.Name);
                                }
                                Result = AuthenticateResult.Success(Ticket);
                            }
                            else
                            {
                                //No se pudo Validar el token
                                Result = AuthenticateResult.Fail(Error);
                            }
                        }
                        catch
                        {
                            Result = AuthenticateResult.Fail(EdDSAJwtBearerErrors.InvalidToken);
                        }
                    }
                }
            }
            return Task.FromResult(Result);
        }
        private bool TryGetPayloadWithTokenValidation(
                    string token, EdDSAJwtBearerOptions options,
                    out Dictionary<string, object> payload, out string error)
        {
            bool IsValid = false;
            payload = default;
            error = string.Empty;
            // Logica de Validacion
            try
              {
                if (EdDSATokenHandler.TryGetPayloadFromToken(token,
                options.PublicSigningKey, out payload))
                {
                    IsValid = true;
                    object Value;
                    if (options.ValidateIssuer)
                    {
                        IsValid = payload.TryGetValue("iss", out Value);
                        if (IsValid)
                        {
                            IsValid = options.ValidIssuer.Equals
                            (Value.ToString(), StringComparison.OrdinalIgnoreCase);
                        }
                      if(!IsValid) error = EdDSAJwtBearerErrors.InvalidIssuer;
                     }
                    if(IsValid && options.ValidateAudience)
                      {
                        IsValid = payload.TryGetValue("exp", out Value);
                        if (IsValid)
                         {
                            string[] Audiences = Value.ToString().Split(",");
                            IsValid = Audiences.Contains(options.ValidAudience);
                         }
                        if(!IsValid) error = EdDSAJwtBearerErrors.InvalidAudience;
                    }
                    if (IsValid && options.ValidateLifetime)
                    {
                        IsValid = payload.TryGetValue("exp", out Value);
                        if (IsValid)
                        {
                            long ExpirationTime = Convert.ToInt64(Value.ToString());
                            IsValid = ExpirationTime > new DateTimeOffset(DateTime.Now).ToUnixTimeSeconds();

                        }
                        if (!IsValid) error = EdDSAJwtBearerErrors.ExpiredToken;
                    }
                }
                else
                {
                    IsValid = false;
                    error = EdDSAJwtBearerErrors.InvalidToken;
                }
            }
            catch
            {
                IsValid = false;
                error = EdDSAJwtBearerErrors.InvalidToken;
            }
            return IsValid;

        }
        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            Response.Headers["WWW-Authenticate"] = "Bearer";
            await base.HandleChallengeAsync(properties);
        }
    }
  }

