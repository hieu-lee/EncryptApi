using System.Text;

namespace EncryptApi.Models
{
    public class Aes128Output
    {
        public string Plaintext { get; set; } = string.Empty;
        public string FirstRoundKey { get; set; }
        public string LastRoundKey { get; set; }
        public string Ciphertext { get; set; } = string.Empty;

        public static Aes128Output ToEncryptOutput(TupleU128 res)
        {
            var enc = Encoding.GetEncoding("iso-8859-1");
            return new()
            {
                Ciphertext = enc.GetString(res.Item1),
                LastRoundKey = enc.GetString(res.Item2)
            };
        }

        public static Aes128Output ToDecryptOutput(TupleU128 res)
        {
            var enc = Encoding.GetEncoding("iso-8859-1");
            return new()
            {
                Plaintext = enc.GetString(res.Item1),
                FirstRoundKey = enc.GetString(res.Item2)
            };
        }
    }
}
