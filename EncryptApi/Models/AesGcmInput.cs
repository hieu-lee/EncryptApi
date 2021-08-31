using System.ComponentModel.DataAnnotations;
using System.Text;

namespace EncryptApi.Models
{
    public class AesGcmInput
    {
        public string Ciphertext { get; set; } = string.Empty;
        public string Plaintext { get; set; } = string.Empty;
        public string Tag { get; set; } = string.Empty;
        public string IV { get; set; } = string.Empty;
        public string Key { get; set; } = string.Empty;
        public string AdditionalData { get; set; } = string.Empty;

        public GcmInput? ToEncryptInput()
        {
            var enc = Encoding.GetEncoding("iso-8859-1");
            var iv = enc.GetBytes(IV);
            var k = enc.GetBytes(Key);
            if (iv.Length != 12 || k.Length != 16)
            {
                return null;
            }
            return new()
            {
                Plaintext = enc.GetBytes(Plaintext),
                IV = iv,
                Key = k,
                AddData = enc.GetBytes(AdditionalData),
            };
        }

        public GcmInput? ToDecryptInput()
        {
            var enc = Encoding.GetEncoding("iso-8859-1");
            var t = enc.GetBytes(Tag);
            var iv = enc.GetBytes(IV);
            var k = enc.GetBytes(Key);
            if (iv.Length != 12 || k.Length != 16 || t.Length != 16)
            {
                return null;
            }
            return new()
            {
                IV = iv,
                Key = k,
                Tag = t,
                AddData = enc.GetBytes(AdditionalData),
                Ciphertext = enc.GetBytes(Ciphertext)
            };
        }
    }
}
