using EncryptApi.Models;
using System;
using System.Threading.Tasks;

namespace EncryptApi.Services
{
    public class AesGcmService
    {
        const int twoP32 = 4294967;

        public static void inc32(byte[] x)
        {
            int lsb = 0;
            lsb |= x[12] << 24;
            lsb |= x[13] << 16;
            lsb |= x[14] << 8;
            lsb |= x[15];

            lsb++;

            int after_mod = lsb % twoP32;

            x[15] = (byte)after_mod;

            after_mod >>= 8;
            x[14] = (byte)after_mod;

            after_mod >>= 8;
            x[13] = (byte)after_mod;

            after_mod >>= 8;
            x[12] = (byte)after_mod;
        }

        public static void right_shift(byte[] v)
        {
            int i;
            int lowestBit, highestBit;
            lowestBit = v[0] & 1;
            v[0] >>= 1;
            highestBit = lowestBit;
            for (i = 1; i < 16; i++)
            {
                lowestBit = v[i] & 1;
                v[i] >>= 1;
                if (highestBit == 1)
                {
                    v[i] |= (1 << 7);
                }
                highestBit = lowestBit;
            }
        }

        public static void xor_block(byte[] dst, byte[] src, int length = 16)
        {
            int i;
            for (i = 0; i < length; i++)
            {
                dst[i] ^= src[i];
            }
        }

        // Return the concatenation of two array
        static T[] concate_block<T>(T[] a, T[] b)
        {
            int u = a.Length;
            int v = b.Length;
            var res = new T[u + v];
            for (int i = 0; i < u; i++)
            {
                res[i] = a[i];
            }
            for (int i = u; i < u + v; i++)
            {
                res[i] = b[i - u];
            }
            return res;
        }

        static byte[] len(byte[] A)
        {
            byte[] res = new byte[8];
            int c = A.Length << 3;
            for (int i = 0; i < 8; i++)
            {
                res[i] = (byte)((c >> ((7 - i) << 3)) & 0xff);
            }
            return res;
        }

        static byte[] g_mult(byte[] X, byte[] Y)
        {
            byte[] V = new byte[16];

            int i, j, lsb;

            byte[] Z = new byte[16]
            {
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0
            };

            for (i = 0; i < 16; i++)
            {
                V[i] = X[i];
            }

            for (i = 0; i < 16; i++)
            {
                for (j = 0; j < 8; j++)
                {
                    if ((Y[i] >> (7 - j)) == 1)
                    {
                        xor_block(Z, V);
                    }

                    lsb = V[15] & 0x01;
                    right_shift(V);
                    if (lsb == 1)
                    {
                        V[0] ^= 0xe1;
                    }
                }
            }

            return Z;
        }

        static byte[] Ghash(byte[] H, byte[] X, int len_X)
        {
            int c;
            var temp = new byte[16];
            for (int i = 0; i < 16; i++)
            {
                temp[i] = X[i];
            }
            var Y = g_mult(H, temp);

            for (int i = 1; i < len_X; i++)
            {
                c = i << 4;
                for (int j = 0; j < 16; j++)
                {
                    temp[j] = X[c + j];
                }
                xor_block(Y, temp);
                Y = g_mult(Y, H);
            }
            return Y;
        }

        static void Gctr(byte[] K, byte[] ICB, byte[] X, int len_X, int last_len_X, byte[] Cipher)
        {
            if (X.Length == 0)
            {
                return;
            }
            int i, j, c;
            byte[] tmp;
            var CB = ICB;

            for (i = 0; i < len_X - 1; i++)
            {
                c = i << 4;
                tmp = Aes128Service.AES128E(CB, K).Item1;
                for (j = 0; j < 16; j++)
                {
                    Cipher[c + j] = (byte)(tmp[j] ^ X[c + j]);
                }
                inc32(CB);
            }

            tmp = Aes128Service.AES128E(CB, K).Item1;
            c = (len_X - 1) << 4;
            for (i = 0; i < last_len_X; i++)
            {
                Cipher[c + i] = (byte)(tmp[i] ^ X[c + i]);
            }
        }

        // Async version of encryption function
        public static async Task<GcmOutput> AES128GCMeAsync(byte[] IV, byte[] _P, byte[] _A, byte[] K)
        {
            var last_len_a = (_A.Length % 16 == 0) ? 16 : _A.Length % 16;
            var last_len_p = (_P.Length % 16 == 0) ? 16 : _P.Length % 16;
            var len_a = (last_len_a == 16) ? (_A.Length >> 4) : (_A.Length >> 4 + 1);
            var len_p = (last_len_p == 16) ? (_P.Length >> 4) : (_P.Length >> 4 + 1);
            var C = new byte[_P.Length];
            var T = new byte[16];
            var H = Aes128Service.AES128E(new byte[16]
            {
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            }, K).Item1;
            var Y0 = new byte[16];
            Y0[12] = 0;
            Y0[13] = 0;
            Y0[14] = 0;
            Y0[15] = 1;
            for (int i = 0; i < 12; i++)
            {
                Y0[i] = IV[i];
            }
            inc32(Y0);
            var task = Task.Factory.StartNew(() =>
            {
                Gctr(K, Y0, _P, len_p, last_len_p, C);
            });
            byte[] temp = concate_block(len(_A), len(C));
            await task;
            len_a <<= 4;
            len_p <<= 4;
            var l = len_a + len_p + 16;
            var tmp = new byte[l];
            for (int i = 0; i < len_a; i++)
            {
                tmp[i] = _A[i];
            }
            for (int i = len_a; i < l - 16; i++)
            {
                tmp[i] = C[i - len_a];
            }
            for (int i = l - 16; i < l; i++)
            {
                tmp[i] = temp[i + 16 - l];
            }
            var S = Ghash(H, tmp, l >> 4);
            Y0[12] = 0;
            Y0[13] = 0;
            Y0[14] = 0;
            Y0[15] = 1;
            for (int i = 0; i < 12; i++)
            {
                Y0[i] = IV[i];
            }
            Gctr(K, Y0, S, 1, 16, T);
            return new(C, T);
        }

        public static AesGcmOutput Encryption(AesGcmInput Input)
        {
            var input = Input.ToEncryptInput();
            if (input is not null)
            {
                var v = input.Value;
                var res = AES128GCMe(v.IV, v.Plaintext, v.AddData, v.Key);
                return AesGcmOutput.ToEncryptOutput(res);
            }
            return null;
        }

        public static async Task<AesGcmOutput> EncryptionAsync(AesGcmInput Input)
        {
            var input = Input.ToEncryptInput();
            if (input is not null)
            {
                var v = input.Value;
                var res = await AES128GCMeAsync(v.IV, v.Plaintext, v.AddData, v.Key);
                return AesGcmOutput.ToEncryptOutput(res);
            }
            return null;
        }

        public static AesGcmOutput Decryption(AesGcmInput Input)
        {
            var input = Input.ToDecryptInput();
            if (input is not null)
            {
                var v = input.Value;
                var res = AES128GCMd(v.IV, v.Ciphertext, v.Key, v.AddData, v.Tag);
                return AesGcmOutput.ToDecryptOutput(res);
            }
            return null;
        }
        public static async Task<AesGcmOutput> DecryptionAsync(AesGcmInput Input)
        {
            var input = Input.ToDecryptInput();
            if (input is not null)
            {
                var v = input.Value;
                var res = await AES128GCMdAsync(v.IV, v.Ciphertext, v.Key, v.AddData, v.Tag);
                return AesGcmOutput.ToDecryptOutput(res);
            }
            return null;
        }

        // Encryption function
        static GcmOutput AES128GCMe(byte[] IV, byte[] _P, byte[] _A, byte[] K)
        {
            var last_len_a = (_A.Length % 16 == 0) ? 16 : _A.Length % 16;
            var last_len_p = (_P.Length % 16 == 0) ? 16 : _P.Length % 16;
            var len_a = (last_len_a == 16) ? (_A.Length >> 4) : (_A.Length >> 4 + 1);
            var len_p = (last_len_p == 16) ? (_P.Length >> 4) : (_P.Length >> 4 + 1);
            var C = new byte[_P.Length];
            var T = new byte[16];
            var H = Aes128Service.AES128E(new byte[16]
            {
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            }, K).Item1;
            var Y0 = new byte[16];
            Y0[12] = 0;
            Y0[13] = 0;
            Y0[14] = 0;
            Y0[15] = 1;
            for (int i = 0; i < 12; i++)
            {
                Y0[i] = IV[i];
            }
            inc32(Y0);
            Gctr(K, Y0, _P, len_p, last_len_p, C);
            byte[] temp = concate_block(len(_A), len(C));
            len_a <<= 4;
            len_p <<= 4;
            var l = len_a + len_p + 16;
            var tmp = new byte[l];
            for (int i = 0; i < len_a; i++)
            {
                tmp[i] = _A[i];
            }
            for (int i = len_a; i < l - 16; i++)
            {
                tmp[i] = C[i - len_a];
            }
            for (int i = l - 16; i < l; i++)
            {
                tmp[i] = temp[i + 16 - l];
            }
            var S = Ghash(H, tmp, l >> 4);
            Y0[12] = 0;
            Y0[13] = 0;
            Y0[14] = 0;
            Y0[15] = 1;
            for (int i = 0; i < 12; i++)
            {
                Y0[i] = IV[i];
            }
            Gctr(K, Y0, S, 1, 16, T);
            return new(C, T);
        }

        // Async version of decryption function
        public static async Task<byte[]> AES128GCMdAsync(byte[] IV, byte[] _C, byte[] K, byte[] _A, byte[] _T)
        {
            var last_len_a = (_A.Length % 16 == 0) ? 16 : _A.Length % 16;
            var last_len_c = (_C.Length % 16 == 0) ? 16 : _C.Length % 16;
            var len_a = (last_len_a == 16) ? (_A.Length >> 4) : (_A.Length >> 4 + 1);
            var len_c = (last_len_c == 16) ? (_C.Length >> 4) : (_C.Length >> 4 + 1);
            var P = new byte[_C.Length];
            var T = new byte[16];
            var H = Aes128Service.AES128E(new byte[16]
            {
                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            }, K).Item1;
            var Y0 = new byte[16];
            Y0[12] = 0;
            Y0[13] = 0;
            Y0[14] = 0;
            Y0[15] = 1;
            for (int i = 0; i < 12; i++)
            {
                Y0[i] = IV[i];
            }
            inc32(Y0);

            var task = Task.Factory.StartNew(() =>
            {
                Gctr(K, Y0, _C, len_c, last_len_c, P);
            });

            byte[] temp = concate_block(len(_A), len(_C));
            await task;
            len_a <<= 4;
            len_c <<= 4;
            var l = len_a + len_c + 16;
            var tmp = new byte[l];
            for (int i = 0; i < len_a; i++)
            {
                tmp[i] = _A[i];
            }
            for (int i = len_a; i < l - 16; i++)
            {
                tmp[i] = _C[i - len_a];
            }
            for (int i = l - 16; i < l; i++)
            {
                tmp[i] = temp[i + 16 - l];
            }
            var S = Ghash(H, tmp, l >> 4);
            Y0[12] = 0;
            Y0[13] = 0;
            Y0[14] = 0;
            Y0[15] = 1;
            for (int i = 0; i < 12; i++)
            {
                Y0[i] = IV[i];
            }
            Gctr(K, Y0, S, 1, 16, T);

            for (int i = 0; i < 16; i++)
            {
                if (T[i] != _T[i])
                {
                    throw UnauthorizedAccessException();
                }
            }
            return P;
        }


        // Decryption function
        static byte[] AES128GCMd(byte[] IV, byte[] _C, byte[] K, byte[] _A, byte[] _T)
        {
            var last_len_a = (_A.Length % 16 == 0) ? 16 : _A.Length % 16;
            var last_len_c = (_C.Length % 16 == 0) ? 16 : _C.Length % 16;
            var len_a = (last_len_a == 16) ? (_A.Length >> 4) : (_A.Length >> 4 + 1);
            var len_c = (last_len_c == 16) ? (_C.Length >> 4) : (_C.Length >> 4 + 1);
            var P = new byte[_C.Length];
            var T = new byte[16];
            var H = Aes128Service.AES128E(new byte[16]
            {
                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            }, K).Item1;
            var Y0 = new byte[16];
            Y0[12] = 0;
            Y0[13] = 0;
            Y0[14] = 0;
            Y0[15] = 1;
            for (int i = 0; i < 12; i++)
            {
                Y0[i] = IV[i];
            }
            inc32(Y0);

            Gctr(K, Y0, _C, len_c, last_len_c, P);

            byte[] temp = concate_block(len(_A), len(_C));
            len_a <<= 4;
            len_c <<= 4;
            var l = len_a + len_c + 16;
            var tmp = new byte[l];
            for (int i = 0; i < len_a; i++)
            {
                tmp[i] = _A[i];
            }
            for (int i = len_a; i < l - 16; i++)
            {
                tmp[i] = _C[i - len_a];
            }
            for (int i = l - 16; i < l; i++)
            {
                tmp[i] = temp[i + 16 - l];
            }
            var S = Ghash(H, tmp, l >> 4);
            Y0[12] = 0;
            Y0[13] = 0;
            Y0[14] = 0;
            Y0[15] = 1;
            for (int i = 0; i < 12; i++)
            {
                Y0[i] = IV[i];
            }
            Gctr(K, Y0, S, 1, 16, T);

            for (int i = 0; i < 16; i++)
            {
                if (T[i] != _T[i])
                {
                    throw UnauthorizedAccessException();
                }
            }
            return P;
        }

        private static Exception UnauthorizedAccessException()
        {
            return new("FAIL");
        }
    }
}
