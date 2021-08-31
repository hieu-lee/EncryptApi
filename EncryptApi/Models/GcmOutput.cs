namespace EncryptApi.Models
{
    public struct GcmOutput
    {
        public byte[] CipherText;
        public byte[] Tag;

        public GcmOutput(byte[] _CipherText, byte[] _Tag)
        {
            CipherText = _CipherText;
            Tag = _Tag;
        }
    }
}
