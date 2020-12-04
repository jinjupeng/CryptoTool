using CryptoTool.Common;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CryptoTool.App
{
    class Program
    {
        static void Main(string[] args)
        {
            string input = "abc";
            input = "银行密码统统都给我";
            string key = "justdoit";
            string result = string.Empty;
            result = Encrypter.EncryptByMD5(input);
            Console.WriteLine("MD5加密结果：{0}", result);

            result = Encrypter.EncryptBySHA1(input);
            Console.WriteLine("SHA1加密结果：{0}", result);

            result = Encrypter.EncryptString(input, key);
            Console.WriteLine("DES加密结果：{0}", result);


            result = Encrypter.DecryptString(result, key);
            Console.WriteLine("DES解密结果：{0}", result);

            result = Encrypter.EncryptByDES(input, key);
            Console.WriteLine("DES加密结果：{0}", result);


            result = Encrypter.DecryptByDES(result, key);
            Console.WriteLine("DES解密结果：{0}", result); //结果："银行密码统统都给我�\nJn7"，与明文不一致，为什么呢？在加密后，通过base64编码转为字符串，可能是这个问题。

            key = "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";

            result = Encrypter.EncryptByAES(input, key);
            Console.WriteLine("AES加密结果：{0}", result);

            result = Encrypter.DecryptByAES(result, key);
            Console.WriteLine("AES解密结果：{0}", result);


            KeyValuePair<string, string> keyPair = Encrypter.CreateRSAKey();
            string privateKey = keyPair.Value;
            string publicKey = keyPair.Key;

            // 公钥加密、私钥解密
            result = Encrypter.EncryptByRSA(input, publicKey);
            Console.WriteLine("RSA公钥加密后的结果：{0}", result);

            result = Encrypter.DecryptByRSA(result, privateKey);
            Console.WriteLine("RSA私钥解密后的结果：{0}", result);

            // 密钥加签，公钥验签
            result = Encrypter.HashAndSignString(input, privateKey);
            Console.WriteLine("RSA私钥加签后的结果：{0}", result);

            bool boolResult = Encrypter.VerifySigned(input, result, publicKey);
            Console.WriteLine("RSA公钥验签后的结果：{0}", boolResult);

            TestSign();
            SignData();
            Console.WriteLine("输入任意键退出！");
            Console.ReadKey();
        }

        /// <summary>
        /// 测试数字签名
        /// </summary>
        public static void TestSign()
        {
            string originalData = "文章不错，这是我的签名：奥巴马！";
            Console.WriteLine("签名数为：{0}", originalData);
            KeyValuePair<string, string> keyPair = Encrypter.CreateRSAKey();
            string privateKey = keyPair.Value;
            string publicKey = keyPair.Key;

            //1、生成签名，通过摘要算法
            string signedData = Encrypter.HashAndSignString(originalData, privateKey);
            Console.WriteLine("数字签名:{0}", signedData);

            //2、验证签名
            bool verify = Encrypter.VerifySigned(originalData, signedData, publicKey);
            Console.WriteLine("签名验证结果：{0}", verify);
        }

        /// <summary>
        /// 加签
        /// </summary>
        public static void SignData()
        {
            string noSignStr = "我要签名";
            string path = @"C:\Users\Administrator\Desktop\数字签名证书.pfx";
            var result = Encrypter.SignData(path, "123456", noSignStr, "MD5");
            // Console.WriteLine("加签结果：{0}", result);

            // byte[] signData = Encoding.Default.GetBytes(result);
            var verifyResult = Encrypter.VerifySign(path, "123456", noSignStr, "MD5", result);

            Console.WriteLine("验签结果：{0}", verifyResult);

            //byte[] messagebytes = Encoding.UTF8.GetBytes("我要签名");
            //string Path = @"C:\Users\Administrator\Desktop\数字证书.pfx";
            //X509Certificate2 x509 = new X509Certificate2(Path, "123456");
            //SHA1 sha1 = new SHA1CryptoServiceProvider();
            //MD5 md5 = MD5.Create();
            //byte[] hashbytes = md5.ComputeHash(messagebytes); //对要签名的数据进行哈希 
            //RSAPKCS1SignatureFormatter signe = new RSAPKCS1SignatureFormatter();
            //signe.SetKey(x509.PrivateKey); //设置签名用到的私钥 
            //signe.SetHashAlgorithm("MD5"); //设置签名算法 
            //byte[] result = signe.CreateSignature(hashbytes);
            //Console.WriteLine("加签结果：{0}", Convert.ToBase64String(result));

            //RSACryptoServiceProvider oRSA4 = new RSACryptoServiceProvider();
            //oRSA4.FromXmlString(x509.PublicKey.Key.ToXmlString(false));
            //bool bVerify = oRSA4.VerifyData(messagebytes, "MD5", result);
            //Console.WriteLine("验签结果：{0}", bVerify);
        }
    }
}
