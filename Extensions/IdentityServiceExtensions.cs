using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

namespace API.Extensions
{
    public static class IdentityServiceExtensions
    {
        public static IServiceCollection AddIdentityServices(this IServiceCollection services
          ,IConfiguration config)
          {
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding
                 .UTF8.GetBytes(config["TokenKey"])),
            ValidateIssuer = false,
            ValidIssuer = "https://localhost:5001",
            ValidateAudience = false,
             ValidAudience = "https://localhost:5001/api"
        };

    });
            return services;
          }
    }
}