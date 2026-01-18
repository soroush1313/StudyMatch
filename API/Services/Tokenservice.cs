using API.Entities;
using API.Interfaces;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace API.Services
{
    public class Tokenservice(IConfiguration config) : ITokenService
    {
        public string CreateToken(AppUser user)
        {
            //create key
            var tokenKey = config["TokenKey"] ?? throw new Exception("Can not get token key");
            if (tokenKey.Length < 64)
                throw new Exception("Your token key needs to be >= 64 characters");
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(tokenKey));

            //create claims
            var claims = new List<Claim>
            {
                new(ClaimTypes.Email, user.Email),
                new(ClaimTypes.NameIdentifier, user.Id),
            };

            //create credentials
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddDays(7),
                SigningCredentials = creds
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}
