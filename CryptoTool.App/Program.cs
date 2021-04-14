using CryptoTool.Common;
using System;
using System.Collections.Generic;

namespace CryptoTool.App
{
    class Program
    {
        static void Main(string[] args)
        {
            //string input = "abc";
            //input = "银行密码统统都给我";
            //string key = "justdoit";
            //string result = string.Empty;
            //result = Encrypter.EncryptByMD5(input);
            //Console.WriteLine("MD5加密结果：{0}", result);

            //result = Encrypter.EncryptBySHA1(input);
            //Console.WriteLine("SHA1加密结果：{0}", result);

            //result = Encrypter.EncryptString(input, key);
            //Console.WriteLine("DES加密结果：{0}", result);


            //result = Encrypter.DecryptString(result, key);
            //Console.WriteLine("DES解密结果：{0}", result);

            //result = Encrypter.EncryptByDES(input, key);
            //Console.WriteLine("DES加密结果：{0}", result);


            //result = Encrypter.DecryptByDES(result, key);
            //Console.WriteLine("DES解密结果：{0}", result); //结果："银行密码统统都给我�\nJn7"，与明文不一致，为什么呢？在加密后，通过base64编码转为字符串，可能是这个问题。

            //key = "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";

            //result = Encrypter.EncryptByAES(input, key);
            //Console.WriteLine("AES加密结果：{0}", result);

            //result = Encrypter.DecryptByAES(result, key);
            //Console.WriteLine("AES解密结果：{0}", result);


            //KeyValuePair<string, string> keyPair = Encrypter.CreateRSAKey();
            //string privateKey = keyPair.Value;
            //string publicKey = keyPair.Key;

            //// 公钥加密、私钥解密
            //result = Encrypter.EncryptByRSA(input, publicKey);
            //Console.WriteLine("RSA公钥加密后的结果：{0}", result);

            //result = Encrypter.DecryptByRSA(result, privateKey);
            //Console.WriteLine("RSA私钥解密后的结果：{0}", result);

            //// 密钥加签，公钥验签
            //result = Encrypter.HashAndSignString(input, privateKey);
            //Console.WriteLine("RSA私钥加签后的结果：{0}", result);

            //bool boolResult = Encrypter.VerifySigned(input, result, publicKey);
            //Console.WriteLine("RSA公钥验签后的结果：{0}", boolResult);

            //TestSign();
            //SignData();

            // 生成自签名的证书路径
            var pfxPath = "D:\\MyROOTCA.pfx";
            //Encrypter.GeneratePfxCertificate(pfxPath);
            var pubPemPath = "D:\\MyROOTCA_Public.pem";
            var priPemPath = "D:\\MyROOTCA_Private.pem";
            //var x509 = Encrypter.GetX509Certificate2();
            //Encrypter.GeneratePublicPemCert(x509, pubPemPath);
            //Encrypter.GeneratePrivatePemCert(x509, priPemPath);

            // 对某个文件计算哈希值
            var filePath = "D:\\归档信息包.zip";
            var hashCode = HashUtil.GetHashCode(filePath);
            Console.WriteLine("文件哈希值：{0}", hashCode);
            // 加签
            var signedPemData = Encrypter.SignDataByPem(priPemPath, hashCode, "MD5");
            var signePfxdData = Encrypter.SignDataByPfx(pfxPath, "123456", hashCode, "MD5");
            Console.WriteLine("Pem加签结果：{0}", signedPemData);
            Console.WriteLine("Pfx加签结果：{0}", signePfxdData);

            var verifyPemResult = Encrypter.VerifySignByPem(pubPemPath, hashCode, "MD5", signedPemData);
            var verifyPfxResult = Encrypter.VerifySignByPfx(pfxPath, "123456", hashCode, "MD5", signePfxdData);
            Console.WriteLine("Pem验签结果：{0}", verifyPemResult);
            Console.WriteLine("Pfx验签结果：{0}", verifyPfxResult);
            Console.WriteLine("输入任意键退出！");
            Console.ReadKey();
        }

        /// <summary>
        /// RSA加签验签测试
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
        /// pfx证书加签验签测试
        /// </summary>
        public static void SignData()
        {
            string noSignStr = "我要签名";
            string path = @"C:\Users\Administrator\Desktop\数字签名证书.pfx";
            var result = Encrypter.SignDataByPfx(path, "123456", noSignStr, "MD5");
            Console.WriteLine("加签结果：{0}", result);

            var verifyResult = Encrypter.VerifySignByPfx(path, "123456", noSignStr, "MD5", result);
            Console.WriteLine("验签结果：{0}", verifyResult);
        }
    }
}
