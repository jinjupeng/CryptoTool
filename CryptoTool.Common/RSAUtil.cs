using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace CryptoTool.Common
{
    public class RSAUtil
    {
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

        #region pfx和pem证书相关



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


#if NETCOREAPP3_0 || NETCOREAPP3_1 || NET5_0 || NET5_0_OR_GREATER

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


#if NETCOREAPP3_0 || NETCOREAPP3_1 || NET5_0 || NET5_0_OR_GREATER

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
            catch (Exception ex)
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


#if NETCOREAPP3_0 || NETCOREAPP3_1 || NET5_0 || NET5_0_OR_GREATER

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

        #endregion
    }
}
