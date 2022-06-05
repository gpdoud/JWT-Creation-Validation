// See https://aka.ms/new-console-template for more information
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

Console.WriteLine("Hello, World!");

var Subject = new ClaimsIdentity(new Claim[]
{
	new Claim("UserRole", "Administrator"),
});

var jwt = GenerateToken(1);
Console.WriteLine(jwt);
var validJwt = ValidateCurrentToken(jwt);
if(validJwt) {
	Console.WriteLine("Valid");
} else {
	Console.WriteLine("Invalid");
}

string GenerateToken(int userId) {
	var mySecret = "asdv234234^&%&^%&^hjsdfb2%%%";
	var mySecurityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(mySecret));
	var myIssuer = "http://mysite.com";
	var myAudience = "http://myaudience.com";
	var tokenHandler = new JwtSecurityTokenHandler();
	var tokenDescriptor = new SecurityTokenDescriptor {
		Subject = new ClaimsIdentity(new Claim[]
		{
			new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
		}),
		Expires = DateTime.UtcNow.AddDays(7),
		Issuer = myIssuer,
		Audience = myAudience,
		SigningCredentials = new SigningCredentials(mySecurityKey, SecurityAlgorithms.HmacSha256Signature)
	};
	var token = tokenHandler.CreateToken(tokenDescriptor);
	return tokenHandler.WriteToken(token);
}

bool ValidateCurrentToken(string token) {
	var mySecret = "asdv234234^&%&^%&^hjsdfb2%%%";
	var mySecurityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(mySecret));
	var myIssuer = "http://mysite.com";
	var myAudience = "http://myaudience.com";
	var tokenHandler = new JwtSecurityTokenHandler();
	try {
		tokenHandler.ValidateToken(token, new TokenValidationParameters {
			ValidateIssuerSigningKey = true,
			ValidateIssuer = true,
			ValidateAudience = true,
			ValidIssuer = myIssuer,
			ValidAudience = myAudience,
			IssuerSigningKey = mySecurityKey
		}, out SecurityToken validatedToken);
	} catch {
		return false;
	}
	return true;
}