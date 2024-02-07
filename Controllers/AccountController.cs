using System.Security.Cryptography;
using System.Text;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController:BaseApiController
    {
        private readonly DataContext _context;
        private readonly ITokenService _tokenService;
         public AccountController(DataContext context,ITokenService tokenService)
         {
            _tokenService = tokenService;
            _context = context;
            
         }
         
         [HttpPost("register")] // POST:/api/account/register
         public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto)
         {
            if (await UserExists(registerDto.Username)) return BadRequest("This UserName is Token (Exists)"); 

            using var hmac = new HMACSHA512();
            var user = new AppUser
            {
                UserName = registerDto.Username.ToLower(),
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
                PasswordSalt = hmac.Key
            }; 
            _context.Users.Add(user);
            await _context.SaveChangesAsync();
         return new UserDto
         {
            Username = user.UserName,
            Token = _tokenService.CreateToken(user)
         };
            
         }

         // log in 
         [HttpPost("login")]
         public async Task<ActionResult <UserDto>>Login(LogInDto loginDto)
         {
            // check username
            var user = await _context.Users.SingleOrDefaultAsync(x => x.UserName == loginDto.Username);

            if (user == null) return Unauthorized("Invalid Username");

            //check password // decoding
            using var hmac = new HMACSHA512(user.PasswordSalt);
            // save the key
            var computeHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));
            // red the key by password
            for (int i= 0; i < computeHash.Length ;i++) 
            {
                if (computeHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid Password");
            }
           return new UserDto
         {
            Username = user.UserName,
            Token = _tokenService.CreateToken(user)
         };


         }
         // check if user name is exisits
         private async Task<bool>UserExists(string username){
            return await _context.Users.AnyAsync(x => x.UserName == username.ToLower());
         }
    }
}