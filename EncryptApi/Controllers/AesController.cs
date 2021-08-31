using EncryptApi.Models;
using EncryptApi.Services;
using Microsoft.AspNetCore.Mvc;
using System;

namespace EncryptApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AesController : ControllerBase
    {
        [HttpPost("encrypt")]
        public IActionResult Encrypt([FromBody] Aes128Input input)
        {
            var res = Aes128Service.Encryption(input);
            if (res is null)
            {
                return StatusCode(403, "Invalid input");
            }
            return Ok(res);
        }

        [HttpPost("decrypt")]
        public IActionResult Decrypt([FromBody] Aes128Input input)
        {
            var res = Aes128Service.Decryption(input);
            if (res is null)
            {
                return StatusCode(403, "Invalid input");
            }
            return Ok(res);
        }
    }
}
