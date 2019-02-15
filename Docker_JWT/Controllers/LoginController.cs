using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Options;
using System.Text;
using System.IdentityModel.Tokens.Jwt;


namespace Docker_JWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private JwtSettings _jwtSettings;
        public LoginController(IOptions<JwtSettings> _jwtSettingsAccesser)
        {
            _jwtSettings=_jwtSettingsAccesser.Value;
        }

        [HttpPost]
        public ActionResult Login([FromBody]loginRequest rq)
        {
            if(rq.username == "admin" && rq.password == "000000")
            {
                var payload = new Claim[]{
                    new Claim("username","admin"),
                    new Claim("isAdmin","true")
                };

                //对称秘钥
                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SecretKey));
                //签名证书(秘钥，加密算法)
                var creds = new SigningCredentials(key,SecurityAlgorithms.HmacSha256);
                
                var token = new JwtSecurityToken(_jwtSettings.Issuer, _jwtSettings.Audience, payload, DateTime.Now, DateTime.Now.AddMinutes(30), creds);
                return Ok(new {token=new JwtSecurityTokenHandler().WriteToken(token)});
            }
            else{
                return Forbid("用户名或密码错误");
            }
        }
    }

    public class loginRequest
    {
        public string username { get; set; }
        public string password { get; set; }
    }
}