using System.Text;

namespace EncryptApi.Models
{
    public class AesGcmOutput
    {
        public string Ciphertext { get; set; } = string.Empty;
        public string Tag { get; set; } = string.Empty;
        public string Plaintext { get; set; } = string.Empty;

        public static AesGcmOutput ToEncryptOutput(GcmOutput res)
        {
            var enc = Encoding.GetEncoding("iso-8859-1");
            return new()
            {
                Ciphertext = enc.GetString(res.CipherText),
                Tag = enc.GetString(res.Tag)
            };
        }

        public static AesGcmOutput ToDecryptOutput(byte[] res)
        {
            var enc = Encoding.GetEncoding("iso-8859-1");
            return new()
            {
                Plaintext = enc.GetString(res)
            };
        }
    }
}
