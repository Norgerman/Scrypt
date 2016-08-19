using System;
using System.Text;
using Xunit;

namespace Norgerman.Cryptography.Scrypt.Test
{
    public class ScryptUtilTest
    {
        [Fact]
        public void Scrypt_Result_Empty_Empty_16_1_1_Test()
        {
            string password;
            byte[] salt;
            int N, r, p, dkLen;
            string DK;

            password = "";
            salt = Encoding.UTF8.GetBytes("");
            N = 16;
            r = 1;
            p = 1;
            dkLen = 64;
            DK = "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906";
            Assert.Equal(DK, 
                BitConverter.ToString(ScryptUtil.Scrypt(password, salt, N, r, p, dkLen))
                .Replace("-", "").ToLower());
        }

        [Fact]
        public void Scrypt_Result_Password_NaCl_1024_8_16_Test()
        {
            string password;
            byte[] salt;
            int N, r, p, dkLen;
            string DK;

            password = "password";
            salt = Encoding.UTF8.GetBytes("NaCl");
            N = 1024;
            r = 8;
            p = 16;
            dkLen = 64;
            DK = "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640";
            Assert.Equal(DK, BitConverter.ToString(ScryptUtil.Scrypt(password, salt, N, r, p, dkLen)).Replace("-", "").ToLower());
        }

        [Fact]
        public void Scrypt_Result_pleaseletmein_SodiumChloride_16384_8_1_Test()
        {
            string password;
            byte[] salt;
            int N, r, p, dkLen;
            string DK;

            password = "pleaseletmein";
            salt = Encoding.UTF8.GetBytes("SodiumChloride");
            N = 16384;
            r = 8;
            p = 1;
            dkLen = 64;
            DK = "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887";
            Assert.Equal(DK, BitConverter.ToString(ScryptUtil.Scrypt(password, salt, N, r, p, dkLen)).Replace("-", "").ToLower());
        }

        [Fact]
        public void Scrypt_Result_pleaseletmein_SodiumChloride_1048576_8_1_Test()
        {
            string password;
            byte[] salt;
            int N, r, p, dkLen;
            string DK;

            password = "pleaseletmein";
            salt = Encoding.UTF8.GetBytes("SodiumChloride");
            N = 1048576;
            r = 8;
            p = 1;
            dkLen = 64;
            DK = "2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa478e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4";
            Assert.Equal(DK, BitConverter.ToString(ScryptUtil.Scrypt(password, salt, N, r, p, dkLen)).Replace("-", "").ToLower());
        }
    }
}
