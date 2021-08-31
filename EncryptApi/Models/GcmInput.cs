namespace EncryptApi.Models
{
    public struct GcmInput
    {
        public byte[] Plaintext { get; set; }
        public byte[] IV { get; set; }
        public byte[] Key { get; set; }
        public byte[] Tag { get; set; }
        public byte[] AddData { get; set; }
        public byte[] Ciphertext { get; set; }
    }
}
