using CryptoTool.Common;
using CryptoTool.Common.GM;
using System;
using System.Collections.Generic;
using System.Text;

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

            //var appkey = Encrypter.GetAppId();
            //var appSecret = Encrypter.EncryptBySHA1(appkey);

            //// 生成自签名的证书路径
            //var pfxPath = "D:\\MyROOTCA.pfx";
            //DataCertificate.ChangePfxCertPassword(pfxPath, "78901234", "123456"); // 修改密码
            ////Encrypter.GeneratePfxCertificate(pfxPath);
            //var pubPemPath = "D:\\MyROOTCA_Public.pem";
            //var priPemPath = "D:\\MyROOTCA_Private.pem";
            ////var x509 = Encrypter.GetX509Certificate2();
            ////Encrypter.GeneratePublicPemCert(x509, pubPemPath);
            ////Encrypter.GeneratePrivatePemCert(x509, priPemPath);

            //// 对某个文件计算哈希值
            //var filePath = "D:\\归档信息包.zip";
            //var hashCode = HashUtil.GetHashCode(filePath);
            //Console.WriteLine("文件哈希值：{0}", hashCode);
            //// 加签
            //var signedPemData = Encrypter.SignDataByPem(priPemPath, hashCode, "MD5");
            ////var signePfxdData = Encrypter.SignDataByPfx(pfxPath, "123456", hashCode, "MD5");
            //Console.WriteLine("Pem加签结果：\n{0}", signedPemData);
            ////Console.WriteLine("Pfx加签结果：\n{0}", signePfxdData);

            //var verifyPemResult = Encrypter.VerifySignByPem(pubPemPath, hashCode, "MD5", signedPemData);
            ////var verifyPfxResult = Encrypter.VerifySignByPfx(pfxPath, "123456", hashCode, "MD5", signePfxdData);
            //Console.WriteLine("Pem验签结果：{0}", verifyPemResult);
            ////Console.WriteLine("Pfx验签结果：{0}", verifyPfxResult);

            SM2Test();
            SM3Test();
            SM4Test();
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

        public static void SM2Test()
        {
            #region 国密SM2加解密测试
            Console.WriteLine("--------------国密SM2非对称加密算法测试---------------");
            string base64PublicKey = "04fd1b00c159476108d81a649eef2c03bf09e63cca59f8fc26c5d8fe58d904cf9abb135fa08a7293ece5e164663ccc26dd77fef19c17779362460d269f36b3ccec";
            string base64PrivateKey = "0af453d26831e0a71cd8d1c2f36a3e3a52b8b30c69fc1944eaf7b216c254c5ea";
            string plainText = "国密SM2非对称加密算法测试";

            var publicKey = SM2Util.ParsePublicKeyFromHex(base64PublicKey);
            var privateKey = SM2Util.ParsePrivateKeyFromHex(base64PrivateKey);
            string cipherText = SM2Util.Encrypt(plainText, publicKey);
            Console.WriteLine("加密结果：" + cipherText);
            string decryptedText = SM2Util.DecryptToString(cipherText, privateKey);
            Console.WriteLine("解密结果：" + decryptedText);

            string sign = SM2Util.SignSm3WithSm2(Encoding.UTF8.GetBytes(plainText), privateKey);
            Console.WriteLine("签名结果：" + sign);
            string isValid = SM2Util.VerifySm3WithSm2(Encoding.UTF8.GetBytes(plainText), sign, publicKey) ? "有效" : "无效";
            Console.WriteLine("验签结果：" + isValid);

            #endregion
        }

        public static void SM3Test()
        {
            Console.WriteLine("--------------国密SM3哈希算法测试---------------");
            string input = "国密SM3哈希算法测试";
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            var hashBytes = SM3Util.ComputeHash(input);
            string hashStr = Convert.ToBase64String(hashBytes);
            Console.WriteLine("哈希结果：" + hashStr);
            bool isValid = SM3Util.VerifyHash(inputBytes, hashBytes);
            Console.WriteLine("哈希验证结果：" + (isValid ? "成功" : "失败"));
        }

        public static void SM4Test()
        {
            #region 国密SM4加解密测试

            Console.WriteLine("--------------国密SM4对称加密算法测试---------------");
            // 加密示例
            string plainText = "这是需要加密的内容";
            string key = "1234567890abcdef"; // 16字节密钥
            string encrypted = SM4Util.EncryptEcb(plainText, key);
            Console.WriteLine("ECB加密结果：" + encrypted);

            // 解密示例
            string decrypted = SM4Util.DecryptEcb(encrypted, key);
            Console.WriteLine("ECB解密结果：" + decrypted);

            // CBC模式示例
            string iv = "fedcba9876543210"; // 16字节初始化向量
            string encryptedCbc = SM4Util.EncryptCbc(plainText, key, iv);
            Console.WriteLine("CBC加密结果：" + encryptedCbc);
            string decryptedCbc = SM4Util.DecryptCbc(encryptedCbc, key, iv);
            Console.WriteLine("CBC解密结果：" + decryptedCbc);

            // 生成随机密钥
            string randomKey = SM4Util.GenerateKey();
            Console.WriteLine("随机密钥：" + randomKey);
            string randomIV = SM4Util.GenerateIV();
            Console.WriteLine("随机IV：" + randomIV);

            #endregion
        }
    }
}
