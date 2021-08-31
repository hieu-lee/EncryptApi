using System.ComponentModel.DataAnnotations;
using System.Text;

namespace EncryptApi.Models
{
    public class Aes128Input
    {
        public string Plaintext { get; set; } = string.Empty;
        public string FirstRoundKey { get; set; }
        public string LastRoundKey { get; set; }
        public string Ciphertext { get; set; } = string.Empty;

        public TupleU128? ToEncryptInput()
        {
            if (string.IsNullOrEmpty(Plaintext) || string.IsNullOrEmpty(FirstRoundKey))
            {
                return null;
            }
            else
            {
                var enc = Encoding.GetEncoding("iso-8859-1");
                byte[] Item1 = enc.GetBytes(Plaintext);
                byte[] Item2 = enc.GetBytes(FirstRoundKey);
                if (Item1.Length != 16 || Item2.Length != 16)
                {
                    return null;
                }
                return new TupleU128(Item1, Item2);
            }
        }

        public TupleU128? ToDecryptInput()
        {
            if (string.IsNullOrEmpty(Ciphertext) || string.IsNullOrEmpty(LastRoundKey))
            {
                return null;
            }
            else
            {
                var enc = Encoding.GetEncoding("iso-8859-1");
                byte[] Item1 = enc.GetBytes(Ciphertext);
                byte[] Item2 = enc.GetBytes(LastRoundKey);
                if (Item1.Length != 16 || Item2.Length != 16)
                {
                    return null;
                }
                return new TupleU128(Item1, Item2);
            }
        }
    }
}
