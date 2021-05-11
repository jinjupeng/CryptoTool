using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CryptoTool.Common
{
    /// <summary>
    /// 加密、解密
    /// </summary>
    public class Encrypter
    {
        //DES默认密钥向量
        private static byte[] DES_IV = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF };
        //AES默认密钥向量   
        public static readonly byte[] AES_IV = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF };

        #region MD5
        /// <summary>
        /// MD5加密为32字符长度的16进制字符串
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static string EncryptByMD5(string input)
        {
            MD5 md5Hasher = MD5.Create();
            byte[] data = md5Hasher.ComputeHash(Encoding.UTF8.GetBytes(input));

            StringBuilder sBuilder = new StringBuilder();
            //将每个字节转为16进制
            for (int i = 0; i < data.Length; i++)
            {
                sBuilder.Append(data[i].ToString("x2"));
            }

            return sBuilder.ToString();
        }
        #endregion

        #region SHA1
        /// <summary>
        /// SHA1加密
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static string EncryptBySHA1(string input)
        {
            SHA1 sha = new SHA1CryptoServiceProvider();
            byte[] bytes = Encoding.Unicode.GetBytes(input);
            byte[] result = sha.ComputeHash(bytes);
            return Convert.ToBase64String(result); // BitConverter.ToString(result);
        }
        #endregion

        #region DES
        /// <summary>
        /// 加密方法
        /// </summary>
        /// <param name="input"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static string EncryptByDES(string input, string key)
        {
            byte[] inputBytes = Encoding.UTF8.GetBytes(input); //Encoding.UTF8.GetBytes(input);
            byte[] keyBytes = ASCIIEncoding.UTF8.GetBytes(key);
            byte[] encryptBytes = EncryptByDES(inputBytes, keyBytes, keyBytes);
            //string result = Encoding.UTF8.GetString(encryptBytes); //无法解码,其加密结果中文出现乱码：d\"�e����(��uπ�W��-��,_�\nJn7 
            //原因：如果明文为中文，UTF8编码两个字节标识一个中文字符，但是加密后，两个字节密文，不一定还是中文字符。
            using (DES des = new DESCryptoServiceProvider())
            {
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        using (StreamWriter writer = new StreamWriter(cs))
                        {
                            writer.Write(inputBytes);
                        }
                    }
                }
            }

            string result = Convert.ToBase64String(encryptBytes);

            return result;
        }
        /// <summary>
        /// DES加密
        /// </summary>
        /// <param name="inputBytes">输入byte数组</param>
        /// <param name="key">密钥，只能是英文字母或数字</param>
        /// <param name="IV">偏移向量</param>
        /// <returns></returns>
        public static byte[] EncryptByDES(byte[] inputBytes, byte[] key, byte[] IV)
        {
            DES des = new DESCryptoServiceProvider();
            //建立加密对象的密钥和偏移量
            des.Key = key;
            des.IV = IV;
            string result = string.Empty;

            //1、如果通过CryptoStreamMode.Write方式进行加密，然后CryptoStreamMode.Read方式进行解密，解密成功。
            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(inputBytes, 0, inputBytes.Length);
                }
                return ms.ToArray();
            }
            //2、如果通过CryptoStreamMode.Write方式进行加密，然后再用CryptoStreamMode.Write方式进行解密，可以得到正确结果
            //3、如果通过CryptoStreamMode.Read方式进行加密，然后再用CryptoStreamMode.Read方式进行解密，无法解密，Error：要解密的数据的长度无效。
            //4、如果通过CryptoStreamMode.Read方式进行加密，然后再用CryptoStreamMode.Write方式进行解密,无法解密，Error：要解密的数据的长度无效。
            //using (MemoryStream ms = new MemoryStream(inputBytes))
            //{
            //    using (CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Read))
            //    {
            //        using (StreamReader reader = new StreamReader(cs))
            //        {
            //            result = reader.ReadToEnd();
            //            return Encoding.UTF8.GetBytes(result);
            //        }
            //    }
            //}
        }
        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="input"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static string DecryptByDES(string input, string key)
        {
            //UTF8无法解密，Error: 要解密的数据的长度无效。
            //byte[] inputBytes = Encoding.UTF8.GetBytes(input);//UTF8乱码，见加密算法
            byte[] inputBytes = Convert.FromBase64String(input);

            byte[] keyBytes = ASCIIEncoding.UTF8.GetBytes(key);
            byte[] resultBytes = DecryptByDES(inputBytes, keyBytes, keyBytes);

            string result = Encoding.UTF8.GetString(resultBytes);

            return result;
        }
        /// <summary>
        /// 解密方法
        /// </summary>
        /// <param name="inputBytes"></param>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <returns></returns>
        public static byte[] DecryptByDES(byte[] inputBytes, byte[] key, byte[] iv)
        {
            DESCryptoServiceProvider des = new DESCryptoServiceProvider();
            //建立加密对象的密钥和偏移量，此值重要，不能修改
            des.Key = key;
            des.IV = iv;

            //通过write方式解密
            //using (MemoryStream ms = new MemoryStream())
            //{
            //    using (CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Write))
            //    {
            //        cs.Write(inputBytes, 0, inputBytes.Length);
            //    }
            //    return ms.ToArray();
            //}

            //通过read方式解密
            using (MemoryStream ms = new MemoryStream(inputBytes))
            {
                using (CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    using (StreamReader reader = new StreamReader(cs))
                    {
                        string result = reader.ReadToEnd();
                        return Encoding.UTF8.GetBytes(result);
                    }
                }
            }

            //错误写法,注意哪个是输出流的位置，如果范围ms，与原文不一致。
            //using (MemoryStream ms = new MemoryStream(inputBytes))
            //{
            //    using (CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Read))
            //    {
            //        cs.Read(inputBytes, 0, inputBytes.Length);
            //    }
            //    return ms.ToArray();
            //}
        }

        /// <summary>
        /// 加密字符串
        /// </summary>
        /// <param name="input"></param>
        /// <param name="sKey"></param>
        /// <returns></returns>
        public static string EncryptString(string input, string sKey)
        {
            byte[] data = Encoding.UTF8.GetBytes(input);
            using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
            {
                des.Key = ASCIIEncoding.ASCII.GetBytes(sKey);
                des.IV = ASCIIEncoding.ASCII.GetBytes(sKey);
                ICryptoTransform desencrypt = des.CreateEncryptor();
                byte[] result = desencrypt.TransformFinalBlock(data, 0, data.Length);
                return BitConverter.ToString(result);
            }
        }
        /// <summary>
        /// 解密字符串
        /// </summary>
        /// <param name="input"></param>
        /// <param name="sKey"></param>
        /// <returns></returns>
        public static string DecryptString(string input, string sKey)
        {
            string[] sInput = input.Split("-".ToCharArray());
            byte[] data = new byte[sInput.Length];
            for (int i = 0; i < sInput.Length; i++)
            {
                data[i] = byte.Parse(sInput[i], NumberStyles.HexNumber);
            }
            using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
            {
                des.Key = ASCIIEncoding.ASCII.GetBytes(sKey);
                des.IV = ASCIIEncoding.ASCII.GetBytes(sKey);
                ICryptoTransform desencrypt = des.CreateDecryptor();
                byte[] result = desencrypt.TransformFinalBlock(data, 0, data.Length);
                return Encoding.UTF8.GetString(result);
            }
        }
        #endregion

        #region AES
        /// <summary>  
        /// AES加密算法  
        /// </summary>  
        /// <param name="input">明文字符串</param>  
        /// <param name="key">密钥</param>  
        /// <returns>字符串</returns>  
        public static string EncryptByAES(string input, string key)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(key.Substring(0, 32));
            using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
            {
                aesAlg.Key = keyBytes;
                aesAlg.IV = AES_IV;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(input);
                        }
                        byte[] bytes = msEncrypt.ToArray();
                        //return Convert.ToBase64String(bytes);//此方法不可用
                        return BitConverter.ToString(bytes);
                    }
                }
            }
        }
        /// <summary>  
        /// AES解密  
        /// </summary>  
        /// <param name="input">密文字节数组</param>  
        /// <param name="key">密钥</param>  
        /// <returns>返回解密后的字符串</returns>  
        public static string DecryptByAES(string input, string key)
        {
            //byte[] inputBytes = Convert.FromBase64String(input); //Encoding.UTF8.GetBytes(input);
            string[] sInput = input.Split("-".ToCharArray());
            byte[] inputBytes = new byte[sInput.Length];
            for (int i = 0; i < sInput.Length; i++)
            {
                inputBytes[i] = byte.Parse(sInput[i], NumberStyles.HexNumber);
            }
            byte[] keyBytes = Encoding.UTF8.GetBytes(key.Substring(0, 32));
            using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
            {
                aesAlg.Key = keyBytes;
                aesAlg.IV = AES_IV;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                using (MemoryStream msEncrypt = new MemoryStream(inputBytes))
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srEncrypt = new StreamReader(csEncrypt))
                        {
                            return srEncrypt.ReadToEnd();
                        }
                    }
                }
            }
        }
        /// <summary> 
        /// AES加密        
        /// </summary> 
        /// <param name="inputdata">输入的数据</param>         
        /// <param name="iv">向量128位</param>         
        /// <param name="strKey">加密密钥</param>         
        /// <returns></returns> 
        public static byte[] EncryptByAES(byte[] inputdata, byte[] key, byte[] iv)
        {
            ////分组加密算法 
            //Aes aes = new AesCryptoServiceProvider();          
            ////设置密钥及密钥向量 
            //aes.Key = key;
            //aes.IV = iv;
            //using (MemoryStream ms = new MemoryStream())
            //{
            //    using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
            //    {
            //        using (StreamWriter writer = new StreamWriter(cs))
            //        {
            //            writer.Write(inputdata);
            //        }
            //        return ms.ToArray(); 
            //    }               
            //}

            using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(inputdata);
                        }
                        byte[] encrypted = msEncrypt.ToArray();
                        return encrypted;
                    }
                }
            }
        }
        /// <summary>         
        /// AES解密         
        /// </summary> 
        /// <param name="inputdata">输入的数据</param>                
        /// <param name="key">key</param>         
        /// <param name="iv">向量128</param> 
        /// <returns></returns> 
        public static byte[] DecryptByAES(byte[] inputBytes, byte[] key, byte[] iv)
        {
            Aes aes = new AesCryptoServiceProvider();
            aes.Key = key;
            aes.IV = iv;
            byte[] decryptBytes;
            using (MemoryStream ms = new MemoryStream(inputBytes))
            {
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    using (StreamReader reader = new StreamReader(cs))
                    {
                        string result = reader.ReadToEnd();
                        decryptBytes = Encoding.UTF8.GetBytes(result);
                    }
                }
            }

            return decryptBytes;
        }
        #endregion

        #region DSA
        #endregion

        #region RSA
        /// <summary>
        /// RSA加密
        /// </summary>
        /// <param name="plaintext">明文</param>
        /// <param name="publicKey">公钥</param>
        /// <returns>密文字符串</returns>
        public static string EncryptByRSA(string plaintext, string publicKey)
        {
            UnicodeEncoding ByteConverter = new UnicodeEncoding();
            byte[] dataToEncrypt = ByteConverter.GetBytes(plaintext);
            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {
                RSA.FromXmlString(publicKey);
                byte[] encryptedData = RSA.Encrypt(dataToEncrypt, false);
                return Convert.ToBase64String(encryptedData);
            }
        }
        /// <summary>
        /// RSA解密
        /// </summary>
        /// <param name="ciphertext">密文</param>
        /// <param name="privateKey">私钥</param>
        /// <returns>明文字符串</returns>
        public static string DecryptByRSA(string ciphertext, string privateKey)
        {
            UnicodeEncoding byteConverter = new UnicodeEncoding();
            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {
                RSA.FromXmlString(privateKey);
                byte[] encryptedData = Convert.FromBase64String(ciphertext);
                byte[] decryptedData = RSA.Decrypt(encryptedData, false);
                return byteConverter.GetString(decryptedData);
            }
        }

        /// <summary>
        /// 数字签名加签
        /// </summary>
        /// <param name="plaintext">原文</param>
        /// <param name="privateKey">私钥</param>
        /// <returns>签名</returns>
        public static string HashAndSignString(string plaintext, string privateKey)
        {
            UnicodeEncoding ByteConverter = new UnicodeEncoding();
            byte[] dataToEncrypt = ByteConverter.GetBytes(plaintext);

            using (RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider())
            {
                RSAalg.FromXmlString(privateKey);
                //使用SHA1进行摘要算法，生成签名
                byte[] encryptedData = RSAalg.SignData(dataToEncrypt, new SHA1CryptoServiceProvider());
                return Convert.ToBase64String(encryptedData);
            }
        }
        /// <summary>
        /// 验证签名
        /// </summary>
        /// <param name="plaintext">原文</param>
        /// <param name="SignedData">签名</param>
        /// <param name="publicKey">公钥</param>
        /// <returns></returns>
        public static bool VerifySigned(string plaintext, string SignedData, string publicKey)
        {
            using (RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider())
            {
                RSAalg.FromXmlString(publicKey);
                UnicodeEncoding ByteConverter = new UnicodeEncoding();
                byte[] dataToVerifyBytes = ByteConverter.GetBytes(plaintext);
                byte[] signedDataBytes = Convert.FromBase64String(SignedData);
                return RSAalg.VerifyData(dataToVerifyBytes, new SHA1CryptoServiceProvider(), signedDataBytes);
            }
        }
        /// <summary>
        /// 获取Key
        /// 键为公钥，值为私钥
        /// </summary>
        /// <returns></returns>
        public static KeyValuePair<string, string> CreateRSAKey()
        {
            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
            string privateKey = RSA.ToXmlString(true);
            string publicKey = RSA.ToXmlString(false);

            return new KeyValuePair<string, string>(publicKey, privateKey);
        }
        #endregion

        #region other
        /// <summary>
        /// 
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static byte[] GetBytes(string input)
        {
            string[] sInput = input.Split("-".ToCharArray());
            byte[] inputBytes = new byte[sInput.Length];
            for (int i = 0; i < sInput.Length; i++)
            {
                inputBytes[i] = byte.Parse(sInput[i], NumberStyles.HexNumber);
            }
            return inputBytes;
        }
        #endregion


        /// <summary>
        /// 根据pfx证书验签
        /// 签名（私钥加签，公钥验签）
        /// 加密（公钥加密，私钥解密）
        /// </summary>
        /// <param name="filePath">证书所在路径</param>
        /// <param name="filePath">保护打开证书私钥的密码</param>
        /// <param name="noSignData">需要签名的字符串</param>
        /// <param name="signAlgorithm">签名算法</param>
        /// <param name="signData">哈希值签名后的值</param>
        /// <returns></returns>
        public static bool VerifySignByPfx(string filePath, string password, string noSignData, string signAlgorithm, string signData)
        {
            bool bVerify;
            try
            {
                if (string.IsNullOrEmpty(filePath))
                {
                    throw new Exception("数字证书不存在！");
                }
                // 找到证书文件
                X509Certificate2 objx5092 = new X509Certificate2(filePath, password);

                byte[] messagebytes = Encoding.UTF8.GetBytes(noSignData);

                RSACryptoServiceProvider oRSA4 = new RSACryptoServiceProvider();
                oRSA4.FromXmlString(objx5092.PublicKey.Key.ToXmlString(false));
                bVerify = oRSA4.VerifyData(messagebytes, signAlgorithm, Convert.FromBase64String(signData));
            }
            catch
            {
                throw new Exception("验签失败！");
            }
            return bVerify;
        }

        /// <summary>
        /// 根据pfx证书加签
        /// 签名（私钥加签，公钥验签）
        /// 加密（公钥加密，私钥解密）
        /// </summary>
        /// <param name="pfxByte">签名证书字节数组</param>
        /// <param name="password">保护打开证书私钥的密码</param>
        /// <param name="noSignData">需要签名的字符串</param>
        /// <param name="signAlgorithm">加签算法</param>
        /// <returns>已签名字符串</returns>
        public static string SignDataByPfx(byte[] pfxByte, string password, string noSignData, string signAlgorithm)
        {
            string signData;
            try
            {
                if (pfxByte.Length == 0)
                {
                    throw new Exception("数字证书不存在！");
                }
                // 找到证书文件
                X509Certificate2 objx5092 = new X509Certificate2(pfxByte, password);
                // 对要签名的数据计算哈希 
                HashAlgorithm hashAlgorithm = HashAlgorithm.Create(signAlgorithm);
                byte[] hashbytes = hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(noSignData));

                RSAPKCS1SignatureFormatter sign = new RSAPKCS1SignatureFormatter();
                sign.SetKey(objx5092.PrivateKey); //设置签名用到的私钥 
                sign.SetHashAlgorithm(signAlgorithm); //设置签名算法 

                // 对哈希进行加签
                var signBytes = sign.CreateSignature(hashbytes);

                // 将加签后的数据进行base64编码，返回的就是已签名的数据 
                signData = Convert.ToBase64String(signBytes);
            }
            catch
            {
                throw new Exception("加签失败！");
            }

            return signData;
        }

        /// <summary>
        /// 根据pfx证书加签
        /// 签名（私钥加签，公钥验签）
        /// 加密（公钥加密，私钥解密）
        /// </summary>
        /// <param name="filePath">签名证书所在路径</param>
        /// <param name="password">保护打开证书私钥的密码</param>
        /// <param name="noSignData">需要签名的字符串</param>
        /// <param name="signAlgorithm">加签算法</param>
        /// <returns>已签名字符串</returns>
        public static string SignDataByPfx(string filePath, string password, string noSignData, string signAlgorithm)
        {
            string signData;
            try
            {
                if (string.IsNullOrEmpty(filePath))
                {
                    throw new Exception("数字证书不存在！");
                }
                // 找到证书文件
                X509Certificate2 objx5092 = new X509Certificate2(filePath, password);
                // 对要签名的数据计算哈希 
                HashAlgorithm hashAlgorithm = HashAlgorithm.Create(signAlgorithm);
                byte[] hashbytes = hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(noSignData));

                RSAPKCS1SignatureFormatter sign = new RSAPKCS1SignatureFormatter();
                sign.SetKey(objx5092.PrivateKey); //设置签名用到的私钥 
                sign.SetHashAlgorithm(signAlgorithm); //设置签名算法 

                // 对哈希进行加签
                var signBytes = sign.CreateSignature(hashbytes);

                // 将加签后的数据进行base64编码，返回的就是已签名的数据 
                signData = Convert.ToBase64String(signBytes);
            }
            catch
            {
                throw new Exception("加签失败！");
            }

            return signData;
        }

        /// <summary>
        /// 根据pem证书验签
        /// 签名（私钥加签，公钥验签）
        /// 加密（公钥加密，私钥解密）
        /// </summary>
        /// <param name="pemByte">证书字节数组</param>
        /// <param name="noSignData">需要签名的字符串</param>
        /// <param name="signAlgorithm">签名算法</param>
        /// <param name="signData">哈希值签名后的值</param>
        /// <returns></returns>
        public static bool VerifySignByPem(byte[] pemByte, string noSignData, string signAlgorithm, string signData)
        {
            bool bVerify;
            try
            {
                if (pemByte.Length == 0)
                {
                    throw new Exception("数字证书不存在！");
                }
                // 找到证书文件
                string publicKeyPem = Encoding.UTF8.GetString(pemByte);


#if NETCOREAPP3_0 || NETCOREAPP3_1 || NET5_0

                // keeping only the payload of the key 
                publicKeyPem = publicKeyPem.Replace("-----BEGIN PUBLIC KEY-----", "");
                publicKeyPem = publicKeyPem.Replace("-----END PUBLIC KEY-----", "");
                byte[] publicKeyRaw = Convert.FromBase64String(publicKeyPem);

                // creating the RSA key 
                RSACryptoServiceProvider provider = new RSACryptoServiceProvider();

                // https://github.com/dotnet/runtime/issues/31091
                provider.ImportSubjectPublicKeyInfo(new ReadOnlySpan<byte>(publicKeyRaw), out _);

#endif

#if NETCOREAPP2_1 || NETCOREAPP2_2

                // creating the RSA key 
                RSACryptoServiceProvider provider = new RSACryptoServiceProvider();

                var xmlPublicKey = ConvertPemToXmlPublicKey(publicKeyPem);
                provider.FromXmlStringExtension(xmlPublicKey);

#endif

                bVerify = provider.VerifyData(Encoding.UTF8.GetBytes(noSignData), signAlgorithm, Convert.FromBase64String(signData));
            }
            catch
            {
                throw new Exception("验签失败！");
            }
            return bVerify;
        }

        /// <summary>
        /// 根据pem证书验签
        /// 签名（私钥加签，公钥验签）
        /// 加密（公钥加密，私钥解密）
        /// </summary>
        /// <param name="pemPath">证书所在路径</param>
        /// <param name="noSignData">需要签名的字符串</param>
        /// <param name="signAlgorithm">签名算法</param>
        /// <param name="signData">哈希值签名后的值</param>
        /// <returns></returns>
        public static bool VerifySignByPem(string pemPath, string noSignData, string signAlgorithm, string signData)
        {
            bool bVerify;
            try
            {
                if (string.IsNullOrEmpty(pemPath))
                {
                    throw new Exception("数字证书不存在！");
                }
                // 找到证书文件
                string publicKeyPem = File.ReadAllText(pemPath);


#if NETCOREAPP3_0 || NETCOREAPP3_1 || NET5_0

                // keeping only the payload of the key 
                publicKeyPem = publicKeyPem.Replace("-----BEGIN PUBLIC KEY-----", "");
                publicKeyPem = publicKeyPem.Replace("-----END PUBLIC KEY-----", "");
                byte[] publicKeyRaw = Convert.FromBase64String(publicKeyPem);

                // creating the RSA key 
                RSACryptoServiceProvider provider = new RSACryptoServiceProvider();

                // https://github.com/dotnet/runtime/issues/31091
                provider.ImportSubjectPublicKeyInfo(new ReadOnlySpan<byte>(publicKeyRaw), out _);

#endif

#if NETCOREAPP2_1 || NETCOREAPP2_2

                // creating the RSA key 
                RSACryptoServiceProvider provider = new RSACryptoServiceProvider();

                var xmlPublicKey = ConvertPemToXmlPublicKey(publicKeyPem);
                provider.FromXmlStringExtension(xmlPublicKey);

#endif

                bVerify = provider.VerifyData(Encoding.UTF8.GetBytes(noSignData), signAlgorithm, Convert.FromBase64String(signData));
            }
            catch(Exception ex)
            {
                throw new Exception("验签失败！");
            }
            return bVerify;
        }

        /// <summary>
        /// 根据pem证书加签
        /// 签名（私钥加签，公钥验签）
        /// 加密（公钥加密，私钥解密）
        /// </summary>
        /// <param name="pemPath">签名证书所在路径</param>
        /// <param name="noSignData">需要签名的字符串</param>
        /// <param name="signAlgorithm">加签算法</param>
        /// <returns>已签名字符串</returns>
        public static string SignDataByPem(string pemPath, string noSignData, string signAlgorithm)
        {
            string signData;
            try
            {
                if (string.IsNullOrEmpty(pemPath))
                {
                    throw new Exception("数字证书不存在！");
                }
                // 找到证书文件
                string privateKeyPem = File.ReadAllText(pemPath);


#if NETCOREAPP3_0 || NETCOREAPP3_1 || NET5_0

                // keeping only the payload of the key 
                privateKeyPem = privateKeyPem.Replace("-----BEGIN RSA PRIVATE KEY-----", "");
                privateKeyPem = privateKeyPem.Replace("-----END RSA PRIVATE KEY-----", "");
                byte[] privateKeyRaw = Convert.FromBase64String(privateKeyPem);

                // creating the RSA key 
                RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
                provider.ImportRSAPrivateKey(new ReadOnlySpan<byte>(privateKeyRaw), out _);

#endif

#if NETCOREAPP2_1 || NETCOREAPP2_2

                // creating the RSA key 
                RSACryptoServiceProvider provider = new RSACryptoServiceProvider();

                var xmlPrivateKey = ConvertPemToXmlPrivateKey(privateKeyPem);
                provider.FromXmlStringExtension(xmlPrivateKey);

#endif

                // 签名
                var signBytes = provider.SignData(Encoding.UTF8.GetBytes(noSignData), signAlgorithm);

                // 将加签后的数据进行base64编码，返回的就是已签名的数据 
                signData = Convert.ToBase64String(signBytes);
            }
            catch (Exception ex)
            {
                throw new Exception("加签失败！");
            }

            return signData;
        }

        /// <summary>
        /// 生成自签名的pfx证书
        /// </summary>
        /// <param name="pfxPath">pfx证书存在路径</param>
        /// <param name="password">pfx证书密码</param>
        public static void GeneratePfxCertificate(string pfxPath, string password = "123456")
        {
            using (FileStream fs = File.Create(pfxPath))
            {
                // var X509Certificate2 = DataCertificate.GenerateSelfSignedCertificate("CN=127.0.0.1", "CN=MyROOTCA");
                var caPrivKey = DataCertificate.GenerateCACertificate("CN=root ca");
                var X509Certificate2 = DataCertificate.GenerateSelfSignedCertificate("CN=127.0.01", "CN=root ca", caPrivKey);
                var pfxArr = X509Certificate2.Export(X509ContentType.Pfx, password);
                fs.Write(pfxArr);
            }
        }


        /// <summary>
        /// 生成证书对象数据
        /// </summary>
        /// <returns></returns>
        public static X509Certificate2 GetX509Certificate2()
        {
            var caPrivKey = DataCertificate.GenerateCACertificate("CN=root ca");
            var X509Certificate2 = DataCertificate.GenerateSelfSignedCertificate("CN=127.0.01", "CN=root ca", caPrivKey);
            return X509Certificate2;
        }

        /// <summary>
        /// 生成公有pem证书
        /// </summary>
        /// <param name="pemPublicPath">公钥证书</param>
        public static void GeneratePublicPemCert(X509Certificate2 x509, string pemPublicPath)
        {
            var rsaPublicKey = x509.GetRSAPublicKey().ToXmlString(false);
            var pemPublicKey = RSAKeyToPem(rsaPublicKey, false);
            if (File.Exists(pemPublicPath))
            {
                File.Delete(pemPublicPath);
            }
            using (FileStream fs = File.Create(pemPublicPath))
            {
                fs.Write(Encoding.UTF8.GetBytes(pemPublicKey));
            }
        }

        /// <summary>
        /// 生成私有pem证书
        /// </summary>
        /// <param name="x509"></param>
        /// <param name="pemPrivatePath"></param>
        public static void GeneratePrivatePemCert(X509Certificate2 x509, string pemPrivatePath)
        {
            var rsaPrivateKey = x509.GetRSAPrivateKey().ToXmlString(true);
            var pemPrivateKey = RSAKeyToPem(rsaPrivateKey, true);
            if (File.Exists(pemPrivatePath))
            {
                File.Delete(pemPrivatePath);
            }
            using (FileStream fs = File.Create(pemPrivatePath))
            {
                fs.Write(Encoding.UTF8.GetBytes(pemPrivateKey));
            }
        }

        /// <summary>
        /// RSA密钥转Pem密钥
        /// </summary>
        /// <param name="RSAKey">RSA密钥</param>
        /// <param name="isPrivateKey">是否是私钥</param>
        /// <returns>Pem密钥</returns>
        public static string RSAKeyToPem(string RSAKey, bool isPrivateKey)
        {
            string pemKey = string.Empty;
            var rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(RSAKey);
            RSAParameters rsaPara = new RSAParameters();
            RsaKeyParameters key;
            //RSA私钥
            if (isPrivateKey)
            {
                rsaPara = rsa.ExportParameters(true);
                key = new RsaPrivateCrtKeyParameters(
                    new BigInteger(1, rsaPara.Modulus), new BigInteger(1, rsaPara.Exponent), new BigInteger(1, rsaPara.D),
                    new BigInteger(1, rsaPara.P), new BigInteger(1, rsaPara.Q), new BigInteger(1, rsaPara.DP), new BigInteger(1, rsaPara.DQ),
                    new BigInteger(1, rsaPara.InverseQ));
            }
            //RSA公钥
            else
            {
                rsaPara = rsa.ExportParameters(false);
                key = new RsaKeyParameters(false,
                    new BigInteger(1, rsaPara.Modulus),
                    new BigInteger(1, rsaPara.Exponent));
            }
            using (TextWriter sw = new StringWriter())
            {
                var pemWriter = new Org.BouncyCastle.OpenSsl.PemWriter(sw);
                pemWriter.WriteObject(key);
                pemWriter.Writer.Flush();
                pemKey = sw.ToString();
            }
            return pemKey;
        }

        /// <summary>
        /// Pem密钥转RSA密钥
        /// </summary>
        /// <param name="pemKey">Pem密钥</param>
        /// <param name="isPrivateKey">是否是私钥</param>
        /// <returns>RSA密钥</returns>
        public static string PemToRSAKey(string pemKey, bool isPrivateKey)
        {
            string rsaKey = string.Empty;
            object pemObject = null;
            RSAParameters rsaPara = new RSAParameters();
            using (StringReader sReader = new StringReader(pemKey))
            {
                var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(sReader);
                pemObject = pemReader.ReadObject();
            }
            //RSA私钥
            if (isPrivateKey)
            {
                RsaPrivateCrtKeyParameters key = (RsaPrivateCrtKeyParameters)((AsymmetricCipherKeyPair)pemObject).Private;
                rsaPara = new RSAParameters
                {
                    Modulus = key.Modulus.ToByteArrayUnsigned(),
                    Exponent = key.PublicExponent.ToByteArrayUnsigned(),
                    D = key.Exponent.ToByteArrayUnsigned(),
                    P = key.P.ToByteArrayUnsigned(),
                    Q = key.Q.ToByteArrayUnsigned(),
                    DP = key.DP.ToByteArrayUnsigned(),
                    DQ = key.DQ.ToByteArrayUnsigned(),
                    InverseQ = key.QInv.ToByteArrayUnsigned(),
                };
            }
            //RSA公钥
            else
            {
                RsaKeyParameters key = (RsaKeyParameters)pemObject;
                rsaPara = new RSAParameters
                {
                    Modulus = key.Modulus.ToByteArrayUnsigned(),
                    Exponent = key.Exponent.ToByteArrayUnsigned(),
                };
            }
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(rsaPara);
            using (StringWriter sw = new StringWriter())
            {
                sw.Write(rsa.ToXmlString(isPrivateKey ? true : false));
                rsaKey = sw.ToString();
            }
            return rsaKey;

        }

        /// <summary>
        /// 把pem私钥转xml格式
        /// </summary>
        /// <param name="privateKey">直接从private pem文件中读取的字符串</param>
        /// <returns></returns>
        public static string ConvertPemToXmlPrivateKey(string privateKey)
        {
            object pemObject = null;
            using (StringReader sReader = new StringReader(privateKey))
            {
                var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(sReader);
                pemObject = pemReader.ReadObject();
            }
            RsaPrivateCrtKeyParameters key = (RsaPrivateCrtKeyParameters)((AsymmetricCipherKeyPair)pemObject).Private;
            string xmlPrivateKey = string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent><P>{2}</P><Q>{3}</Q><DP>{4}</DP><DQ>{5}</DQ><InverseQ>{6}</InverseQ><D>{7}</D></RSAKeyValue>",
            Convert.ToBase64String(key.Modulus.ToByteArrayUnsigned()),
            Convert.ToBase64String(key.PublicExponent.ToByteArrayUnsigned()),
            Convert.ToBase64String(key.P.ToByteArrayUnsigned()),
            Convert.ToBase64String(key.Q.ToByteArrayUnsigned()),
            Convert.ToBase64String(key.DP.ToByteArrayUnsigned()),
            Convert.ToBase64String(key.DQ.ToByteArrayUnsigned()),
            Convert.ToBase64String(key.QInv.ToByteArrayUnsigned()),
            Convert.ToBase64String(key.Exponent.ToByteArrayUnsigned()));
            return xmlPrivateKey;
        }

        /// <summary>
        /// 把pem公钥转换成xml格式
        /// </summary>
        /// <param name="publicKey">直接从public pem文件中读取出的字符串</param>
        /// <returns></returns>
        public static string ConvertPemToXmlPublicKey(string publicKey)
        {
            object pemObject = null;
            using (StringReader sReader = new StringReader(publicKey))
            {
                var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(sReader);
                pemObject = pemReader.ReadObject();
            }
            RsaKeyParameters key = (RsaKeyParameters)pemObject;
            string xmlpublicKey = string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent></RSAKeyValue>",
            Convert.ToBase64String(key.Modulus.ToByteArrayUnsigned()),
            Convert.ToBase64String(key.Exponent.ToByteArrayUnsigned()));
            return xmlpublicKey;
        }

        /// <summary>
        /// 生成appId
        /// </summary>
        /// <returns></returns>
        public static string GetAppId()
        {
            // https://stackoverflow.com/questions/14412132/whats-the-best-approach-for-generating-a-new-api-key
            var key = new byte[32];
            using (var generator = RandomNumberGenerator.Create())
                generator.GetBytes(key);
            string apiKey = Convert.ToBase64String(key);
            return apiKey;
        }

        /// <summary>
        /// 生成appSecret
        /// </summary>
        /// <returns></returns>
        public static string GetAppSecret()
        {
            return "";
        }

    }
}