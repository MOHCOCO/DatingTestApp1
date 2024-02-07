using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using API.Entities;
using API.Interfaces;
using Microsoft.IdentityModel.Tokens;


namespace API.Services
{
    public class TokenService : ITokenService
    {
        private readonly SymmetricSecurityKey _key;
        public TokenService(IConfiguration config)
        {
             var tokenKey = config["TokenKey"];
            
            // Ensure that the key exists and has sufficient length
            if (string.IsNullOrEmpty(tokenKey) || Encoding.UTF8.GetBytes(tokenKey).Length < 64)
            {
                // If the key is missing or insufficient, generate a new random key
                byte[] keyBytes = new byte[64]; // 512 bits
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(keyBytes);
                }
                _key = new SymmetricSecurityKey(keyBytes);
            }
            else
            {
                // Use the key retrieved from configuration
                _key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(tokenKey));
            }
        }
        public string CreateToken(AppUser user)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.NameId,user.UserName)
            };

            var creds = new SigningCredentials(_key,SecurityAlgorithms.HmacSha512Signature);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddDays(7),
                SigningCredentials = creds

            };
            var tokenHandler = new JwtSecurityTokenHandler();

            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);

        }
    }
}