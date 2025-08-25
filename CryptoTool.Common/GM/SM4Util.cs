using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using System;

namespace CryptoTool.Common.GM
{
    public class SM4Util
    {
        private static readonly string ENCODING = "UTF-8";
        private static readonly string ALGORITHM_NAME = "SM4";
        // 加密算法/分组加密模式/分组填充方式
        // PKCS5Padding-以8个字节为一组进行分组加密
        // 定义分组加密模式使用：PKCS5Padding
        public static readonly string ALGORITHM_NAME_ECB_PADDING = "SM4/ECB/PKCS5Padding";
        public static readonly string SM4_ECB_NOPADDING = "SM4/ECB/NoPadding";
        public static readonly string SM4_CBC_NOPADDING = "SM4/CBC/NoPadding";
        public static readonly string SM4_CBC_PKCS7PADDING = "SM4/CBC/PKCS7Padding";
        // 128-32位16进制；256-64位16进制
        public static readonly int DEFAULT_KEY_SIZE = 128;

        public static byte[] DecryptCBC(byte[] keyBytes, byte[] cipher, byte[] iv, string algo)
        {
            if (keyBytes.Length != 16) throw new ArgumentException("err key length");
            if (cipher.Length % 16 != 0 && algo.Contains("NoPadding")) throw new ArgumentException("err data length");

            try
            {
                KeyParameter key = ParameterUtilities.CreateKeyParameter(ALGORITHM_NAME, keyBytes);
                IBufferedCipher c = CipherUtilities.GetCipher(algo);
                if (iv == null) iv = ZeroIv(algo);
                c.Init(false, new ParametersWithIV(key, iv));
                return c.DoFinal(cipher);
            }
            catch (Exception e)
            {
                return null;
            }
        }


        public static byte[] EncryptCBC(byte[] keyBytes, byte[] plain, byte[] iv, string algo)
        {
            if (keyBytes.Length != 16) throw new ArgumentException("err key length");
            if (plain.Length % 16 != 0 && algo.Contains("NoPadding")) throw new ArgumentException("err data length");

            try
            {
                KeyParameter key = ParameterUtilities.CreateKeyParameter(ALGORITHM_NAME, keyBytes);
                IBufferedCipher c = CipherUtilities.GetCipher(algo);
                if (iv == null) iv = ZeroIv(algo);
                c.Init(true, new ParametersWithIV(key, iv));
                return c.DoFinal(plain);
            }
            catch (Exception e)
            {
                return null;
            }
        }


        public static byte[] EncryptECB(byte[] keyBytes, byte[] plain, string algo)
        {
            if (keyBytes.Length != 16) throw new ArgumentException("err key length");
            //NoPadding 的情况下需要校验数据长度是16的倍数.
            if (plain.Length % 16 != 0 && algo.Contains("NoPadding")) throw new ArgumentException("err data length");

            try
            {
                KeyParameter key = ParameterUtilities.CreateKeyParameter(ALGORITHM_NAME, keyBytes);
                IBufferedCipher c = CipherUtilities.GetCipher(algo);
                c.Init(true, key);
                return c.DoFinal(plain);
            }
            catch (Exception e)
            {
                return null;
            }
        }

        public static byte[] DecryptECB(byte[] keyBytes, byte[] cipher, string algo)
        {
            if (keyBytes.Length != 16) throw new ArgumentException("err key length");
            if (cipher.Length % 16 != 0 && algo.Contains("NoPadding")) throw new ArgumentException("err data length");

            try
            {
                KeyParameter key = ParameterUtilities.CreateKeyParameter(ALGORITHM_NAME, keyBytes);
                IBufferedCipher c = CipherUtilities.GetCipher(algo);
                c.Init(false, key);
                return c.DoFinal(cipher);
            }
            catch (Exception e)
            {
                return null;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="srcByte">已解密的数组</param>
        /// <returns></returns>
        public static string DecryptEcbBase64(byte[] srcByte)
        {
            return Convert.ToBase64String(srcByte);
        }


        public static byte[] ZeroIv(string algo)
        {

            try
            {
                IBufferedCipher cipher = CipherUtilities.GetCipher(algo);
                int blockSize = cipher.GetBlockSize();
                byte[] iv = new byte[blockSize];
                Arrays.Fill(iv, 0);
                return iv;
            }
            catch (Exception e)
            {
                return null;
            }
        }
    }
}
