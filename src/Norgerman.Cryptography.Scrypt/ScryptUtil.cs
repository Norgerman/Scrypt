using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System;
using System.Text;

namespace Norgerman.Cryptography.Scrypt
{
    public static class ScryptUtil
    {
        public static byte[] Scrypt(byte[] password, byte[] salt, int N, int r, int p, int dkLen)
        {
            return Scrypt(Encoding.UTF8.GetString(password), salt, N, r, p, dkLen);
        }

        public static byte[] Scrypt(string password, byte[] salt, int N, int r, int p, int dkLen)
        {
            if (N < 2 || (N & (N - 1)) != 0) throw new ArgumentException("N must be a power of 2 greater than 1", nameof(N));

            if (N > int.MaxValue / 128 / r) throw new ArgumentException("Parameter N is too large", nameof(N));
            if (r > int.MaxValue / 128 / p) throw new ArgumentException("Parameter r is too large", nameof(r));

            byte[] DK;

            byte[] B;
            byte[] XY = new byte[256 * r];
            byte[] V = new byte[128 * r * N];
            int i;

            B = KeyDerivation.Pbkdf2(password, salt, KeyDerivationPrf.HMACSHA256, 1, p * 128 * r);

            for (i = 0; i < p; i++)
            {
                Smix(B, i * 128 * r, r, N, V, XY);
            }

            DK = KeyDerivation.Pbkdf2(password, B, KeyDerivationPrf.HMACSHA256, 1, dkLen);
            return DK;
        }

        private static void Smix(byte[] B, int Bi, int r, int N, byte[] V, byte[] XY)
        {
            int Xi = 0;
            int Yi = 128 * r;
            int i;

            Buffer.BlockCopy(B, Bi, XY, Xi, 128 * r);

            for (i = 0; i < N; i++)
            {
                Buffer.BlockCopy(XY, Xi, V, i * (128 * r), 128 * r);
                BlockmixSalsa8(XY, Xi, Yi, r);
            }

            for (i = 0; i < N; i++)
            {
                int j = Integerify(XY, Xi, r) & (N - 1);
                Blockxor(V, j * (128 * r), XY, Xi, 128 * r);
                BlockmixSalsa8(XY, Xi, Yi, r);
            }

            Buffer.BlockCopy(XY, Xi, B, Bi, 128 * r);
        }

        private static void BlockmixSalsa8(byte[] BY, int Bi, int Yi, int r)
        {
            byte[] X = new byte[64];
            int i;

            Buffer.BlockCopy(BY, Bi + (2 * r - 1) * 64, X, 0, 64);

            for (i = 0; i < 2 * r; i++)
            {
                Blockxor(BY, i * 64, X, 0, 64);
                Salsa20_8(X);
                Buffer.BlockCopy(X, 0, BY, Yi + (i * 64), 64);
            }

            for (i = 0; i < r; i++)
            {
                Buffer.BlockCopy(BY, Yi + (i * 2) * 64, BY, Bi + (i * 64), 64);
            }

            for (i = 0; i < r; i++)
            {
                Buffer.BlockCopy(BY, Yi + (i * 2 + 1) * 64, BY, Bi + (i + r) * 64, 64);
            }
        }

        private static uint R(uint a, int b)
        {
            return (a << b) | (a >> (32 - b));
        }

        unsafe private static void Salsa20_8(byte[] B)
        {
            fixed (byte* bptr = B)
            {
                uint* uptr = (uint*)bptr;
                uint[] x = new uint[16];
                for (int i = 0; i < 16; i++)
                {
                    x[i] = uptr[i];
                }
                for (int i = 0; i < 8; i += 2)
                {
                    x[4] ^= R(x[0] + x[12], 7); x[8] ^= R(x[4] + x[0], 9);
                    x[12] ^= R(x[8] + x[4], 13); x[0] ^= R(x[12] + x[8], 18);

                    x[9] ^= R(x[5] + x[1], 7); x[13] ^= R(x[9] + x[5], 9);
                    x[1] ^= R(x[13] + x[9], 13); x[5] ^= R(x[1] + x[13], 18);

                    x[14] ^= R(x[10] + x[6], 7); x[2] ^= R(x[14] + x[10], 9);
                    x[6] ^= R(x[2] + x[14], 13); x[10] ^= R(x[6] + x[2], 18);

                    x[3] ^= R(x[15] + x[11], 7); x[7] ^= R(x[3] + x[15], 9);
                    x[11] ^= R(x[7] + x[3], 13); x[15] ^= R(x[11] + x[7], 18);

                    /* Operate on rows. */
                    x[1] ^= R(x[0] + x[3], 7); x[2] ^= R(x[1] + x[0], 9);
                    x[3] ^= R(x[2] + x[1], 13); x[0] ^= R(x[3] + x[2], 18);

                    x[6] ^= R(x[5] + x[4], 7); x[7] ^= R(x[6] + x[5], 9);
                    x[4] ^= R(x[7] + x[6], 13); x[5] ^= R(x[4] + x[7], 18);

                    x[11] ^= R(x[10] + x[9], 7); x[8] ^= R(x[11] + x[10], 9);
                    x[9] ^= R(x[8] + x[11], 13); x[10] ^= R(x[9] + x[8], 18);

                    x[12] ^= R(x[15] + x[14], 7); x[13] ^= R(x[12] + x[15], 9);
                    x[14] ^= R(x[13] + x[12], 13); x[15] ^= R(x[14] + x[13], 18);
                }

                for (int i = 0; i < 16; i++)
                    uptr[i] += x[i];
            }
        }

        private static void Blockxor(byte[] S, int Si, byte[] D, int Di, int len)
        {
            for (int i = 0; i < len; i++)
            {
                D[Di + i] ^= S[Si + i];
            }
        }

        unsafe private static int Integerify(byte[] B, int Bi, int r)
        {
            int n;
            fixed (byte* bptr = B)
            {
                Bi += (2 * r - 1) * 64;
                byte* start = bptr + Bi;
                int* iptr = (int*)start;

                n = *iptr;
            }

            return n;
        }
    }
}
