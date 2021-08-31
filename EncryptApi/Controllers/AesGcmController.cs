using EncryptApi.Models;
using EncryptApi.Services;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Threading.Tasks;

namespace EncryptApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AesGcmController : ControllerBase
    {
        [HttpPost("encrypt")]
        public IActionResult Encrypt(AesGcmInput Input)
        {
            var res = AesGcmService.Encryption(Input);
            if (res is null)
            {
                return StatusCode(403, "Invalid input");
            }
            return Ok(res);
        }

        [HttpPost("encrypt-async")]
        public async Task<IActionResult> EncryptAsync(AesGcmInput Input)
        {
            var res = await AesGcmService.EncryptionAsync(Input);
            if (res is null)
            {
                return StatusCode(403, "Invalid input");
            }
            return Ok(res);
        }

        [HttpPost("decrypt")]
        public IActionResult Decrypt(AesGcmInput Input)
        {
            try
            {
                var res = AesGcmService.Decryption(Input);
                if (res is null)
                {
                    return StatusCode(403, "Invalid input");
                }
                return Ok(res);
            }
            catch (Exception)
            {
                return Unauthorized("Incorrect Tag");
            }
        }

        [HttpPost("decrypt-async")]
        public async Task<IActionResult> DecryptAsync(AesGcmInput Input)
        {
            try
            {
                var res = await AesGcmService.DecryptionAsync(Input);
                if (res is null)
                {
                    return StatusCode(403, "Invalid input");
                }
                return Ok(res);
            }
            catch (Exception)
            {
                return Unauthorized("Incorrect Tag");
            }
        }
    }
}
