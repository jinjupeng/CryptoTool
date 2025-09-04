using CryptoTool.Common;
using CryptoTool.Common.GM;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace CryptoTool.App
{
    class Program
    {
        static void Main(string[] args)
        {
            AESTest();
            DESTest();
            //SM2Test();
            //SM3Test();
            //SM4Test();
            Console.WriteLine("输入任意键退出！");
            Console.ReadKey();
        }

        public static void CertTest()
        {
            Console.WriteLine("--------------证书算法测试---------------");

            //// 生成自签名的证书路径
            var pfxPath = "D:\\MyROOTCA.pfx";
            DataCertificate.ChangePfxCertPassword(pfxPath, "78901234", "123456"); // 修改密码
            RSAUtil.GeneratePfxCertificate(pfxPath);
            var pubPemPath = "D:\\MyROOTCA_Public.pem";
            var priPemPath = "D:\\MyROOTCA_Private.pem";
            var x509 = RSAUtil.GetX509Certificate2();
            RSAUtil.GeneratePublicPemCert(x509, pubPemPath);
            RSAUtil.GeneratePrivatePemCert(x509, priPemPath);

            // 对某个文件计算哈希值
            var filePath = "D:\\test.zip";
            var hashCode = HashUtil.GetHashCode(filePath);
            Console.WriteLine("文件哈希值：{0}", hashCode);
            // 加签
            var signedPemData = RSAUtil.SignDataByPem(priPemPath, hashCode, "MD5");
            //var signePfxdData = RSAUtil.SignDataByPfx(pfxPath, "123456", hashCode, "MD5");
            Console.WriteLine("Pem加签结果：\n{0}", signedPemData);
            //Console.WriteLine("Pfx加签结果：\n{0}", signePfxdData);

            var verifyPemResult = RSAUtil.VerifySignByPem(pubPemPath, hashCode, "MD5", signedPemData);
            //var verifyPfxResult = RSAUtil.VerifySignByPfx(pfxPath, "123456", hashCode, "MD5", signePfxdData);
            Console.WriteLine("Pem验签结果：{0}", verifyPemResult);
        }

        public static void MD5Test()
        {
            Console.WriteLine("--------------MD5算法测试---------------");
            string input = "MD5加密算法测试";
            string result = MD5Util.EncryptByMD5(input);
            Console.WriteLine("MD5加密结果：{0}", result);
        }

        public static void SHA1Test()
        {
            Console.WriteLine("\n--------------SHA1算法测试---------------");
            string input = "SHA1加密算法测试";
            string result = SHA1Util.EncryptBySHA1(input);
            Console.WriteLine("SHA1加密结果：{0}", result);
        }

        public static void DESTest()
        {
            Console.WriteLine("\n--------------DES算法测试---------------");
            string key = "justdoit";
            string input = "DES对称加密算法测试";
            string encryptResult = DESUtil.EncryptByDES(input, key); // DESUtil.EncryptString(input, key);
            Console.WriteLine("DES加密结果：{0}", encryptResult);
            string decrptResult = DESUtil.DecryptByDES(encryptResult, key); //DESUtil.DecryptString(encryptResult, key);
            Console.WriteLine("DES解密结果：{0}", decrptResult);
        }

        public static void AESTest()
        {
            Console.WriteLine("\n--------------AES算法测试---------------");
            string key = "aeskeyaeskeyaeskeyaeskeyaeskeyaeskey";
            string input = "AES对称加密算法测试";
            string encryptResult = AESUtil.EncryptByAES(input, key);
            Console.WriteLine("AES加密结果：{0}", encryptResult);

            string decrptResult = AESUtil.DecryptByAES(encryptResult, key);
            Console.WriteLine("AES解密结果：{0}", decrptResult);
        }

        /// <summary>
        /// RSA加签验签测试
        /// </summary>
        public static void RSATest()
        {
            Console.WriteLine("\n--------------RSA算法测试---------------");
            string input = "文章不错，这是我的签名：奥巴马！";
            Console.WriteLine("签名数为：{0}", input);
            KeyValuePair<string, string> keyPair = RSAUtil.CreateRSAKey();
            string privateKey = keyPair.Value;
            string publicKey = keyPair.Key;

            // 密钥加签，公钥验签
            string hashSignResult = RSAUtil.HashAndSignString(input, privateKey);
            Console.WriteLine("RSA私钥加签后的结果：{0}", hashSignResult);

            bool boolResult = RSAUtil.VerifySigned(input, hashSignResult, publicKey);
            Console.WriteLine("RSA公钥验签后的结果：{0}", boolResult);

            // 公钥加密、私钥解密
            string encryptResult = RSAUtil.EncryptByRSA(input, publicKey);
            Console.WriteLine("RSA公钥加密后的结果：{0}", encryptResult);

            string decryptResult = RSAUtil.DecryptByRSA(encryptResult, privateKey);
            Console.WriteLine("RSA私钥解密后的结果：{0}", decryptResult);

        }

        /// <summary>
        /// pfx证书加签验签测试
        /// </summary>
        public static void SignByPfxTest()
        {
            Console.WriteLine("\n--------------pfx证书签名算法测试---------------");
            string noSignStr = "我要签名";
            string path = @"C:\Users\Administrator\Desktop\数字签名证书.pfx";
            var result = RSAUtil.SignDataByPfx(path, "123456", noSignStr, "MD5");
            Console.WriteLine("加签结果：{0}", result);

            var verifyResult = RSAUtil.VerifySignByPfx(path, "123456", noSignStr, "MD5", result);
            Console.WriteLine("验签结果：{0}", verifyResult);
        }

        public static void SM2Test()
        {
            #region 国密SM2加解密测试

            Console.WriteLine("\n--------------国密SM2非对称加密算法测试---------------");
            string plainText = "国密SM2非对称加密算法测试";
            Console.WriteLine($"原文: \"{plainText}\"");

            // 使用新生成的密钥对进行测试，确保结果的通用性
            var keyPair = SM2Util.GenerateKeyPair();
            var publicKey = (Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters)keyPair.Public;
            var privateKey = (Org.BouncyCastle.Crypto.Parameters.ECPrivateKeyParameters)keyPair.Private;

            // 输出密钥信息（便于与Java对比测试）
            Console.WriteLine($"公钥 (Hex): {SM2Util.PublicKeyToHex(publicKey)}");
            Console.WriteLine($"私钥 (Hex): {SM2Util.PrivateKeyToHex(privateKey)}");

            // 默认C1C3C2格式加解密
            string cipherText_C1C3C2 = SM2Util.Encrypt(plainText, publicKey, format: SM2Util.SM2CipherFormat.C1C3C2);
            Console.WriteLine("C1C3C2 加密结果: " + cipherText_C1C3C2);
            string decryptedText_C1C3C2 = SM2Util.DecryptToString(cipherText_C1C3C2, privateKey, format: SM2Util.SM2CipherFormat.C1C3C2);
            Console.WriteLine("C1C3C2 解密结果: " + decryptedText_C1C3C2);
            Console.WriteLine($"C1C3C2 验证: {(plainText == decryptedText_C1C3C2 ? "成功" : "失败")}");

            // ASN.1格式加解密
            string cipherText_ASN1 = SM2Util.Encrypt(plainText, publicKey, format: SM2Util.SM2CipherFormat.ASN1);
            Console.WriteLine("ASN.1 加密结果: " + cipherText_ASN1);
            string decryptedText_ASN1 = SM2Util.DecryptToString(cipherText_ASN1, privateKey, format: SM2Util.SM2CipherFormat.ASN1);
            Console.WriteLine("ASN.1 解密结果: " + decryptedText_ASN1);
            Console.WriteLine($"ASN.1 验证: {(plainText == decryptedText_ASN1 ? "成功" : "失败")}");

            #endregion

            #region Java兼容性加解密测试

            Console.WriteLine("\n--------------Java兼容性加解密测试---------------");

            // 生成Java兼容的密文（自动移除0x04前缀）
            string javaCompatibleCiphertext = SM2Util.EncryptForJava(plainText, publicKey, format: SM2Util.SM2CipherFormat.C1C3C2);
            Console.WriteLine("Java兼容密文: " + javaCompatibleCiphertext);

            // 使用Java兼容解密方法
            string decryptedFromJava = SM2Util.DecryptFromJavaToString(javaCompatibleCiphertext, privateKey, format: SM2Util.SM2CipherFormat.C1C3C2);
            Console.WriteLine("Java兼容解密结果: " + decryptedFromJava);
            Console.WriteLine($"Java兼容性验证: {(plainText == decryptedFromJava ? "成功" : "失败")}");

            // 测试智能解密功能
            Console.WriteLine("\n--- 智能解密测试 ---");

            // 测试.NET格式密文
            Console.WriteLine("测试.NET格式密文智能解密:");
            string smartDecrypt1 = SM2Util.SmartDecryptToString(cipherText_C1C3C2, privateKey, format: SM2Util.SM2CipherFormat.C1C3C2);
            Console.WriteLine($"智能解密结果: {smartDecrypt1}");
            Console.WriteLine($"智能解密验证: {(plainText == smartDecrypt1 ? "成功" : "失败")}");

            // 测试Java格式密文
            Console.WriteLine("测试Java格式密文智能解密:");
            string smartDecrypt2 = SM2Util.SmartDecryptToString(javaCompatibleCiphertext, privateKey, format: SM2Util.SM2CipherFormat.C1C3C2);
            Console.WriteLine($"智能解密结果: {smartDecrypt2}");
            Console.WriteLine($"智能解密验证: {(plainText == smartDecrypt2 ? "成功" : "失败")}");

            // 密文格式检测测试
            Console.WriteLine("\n--- 密文格式检测测试 ---");
            byte[] dotNetBytes = Convert.FromBase64String(cipherText_C1C3C2);
            byte[] javaBytes = Convert.FromBase64String(javaCompatibleCiphertext);

            bool isDotNetFormat = !SM2Util.IsJavaFormat(dotNetBytes, SM2Util.SM2CipherFormat.C1C3C2);
            bool isJavaFormat = SM2Util.IsJavaFormat(javaBytes, SM2Util.SM2CipherFormat.C1C3C2);

            Console.WriteLine($".NET密文格式检测: {(isDotNetFormat ? ".NET格式" : "Java格式")}");
            Console.WriteLine($"Java密文格式检测: {(isJavaFormat ? "Java格式" : ".NET格式")}");
            Console.WriteLine($"密文格式检测验证: {(isDotNetFormat && isJavaFormat ? "成功" : "失败")}");

            #endregion


            #region 国密SM2签名验签测试

            Console.WriteLine("\n--------------国密SM2签名与验签测试---------------");
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);

            // 先生成ASN.1格式签名，然后转换为RS格式（确保使用同一个签名值）
            string sign_ASN1 = SM2Util.SignSm3WithSm2(plainTextBytes, privateKey, SM2Util.SM2SignatureFormat.ASN1);
            Console.WriteLine("ASN.1 签名结果: " + sign_ASN1);
            bool isValid_ASN1 = SM2Util.VerifySm3WithSm2(plainTextBytes, sign_ASN1, publicKey, SM2Util.SM2SignatureFormat.ASN1);
            Console.WriteLine("ASN.1 验签结果: " + (isValid_ASN1 ? "有效" : "无效"));

            // 从ASN.1签名转换为RS格式
            string sign_RS = SM2Util.ConvertHexAsn1ToHexRs(sign_ASN1);
            Console.WriteLine("RS 签名结果 (从ASN.1转换): " + sign_RS);
            bool isValid_RS = SM2Util.VerifySm3WithSm2(plainTextBytes, sign_RS, publicKey, SM2Util.SM2SignatureFormat.RS);
            Console.WriteLine("RS 验签结果: " + (isValid_RS ? "有效" : "无效"));

            #endregion

            #region 密文格式转换测试 (C1C2C3 <-> C1C3C2 <-> ASN.1)
            Console.WriteLine("\n--------------SM2密文格式转换测试---------------");

            // 1. 使用C1C2C3格式加密作为基准
            string c1c2c3_base64 = SM2Util.Encrypt(plainText, publicKey, format: SM2Util.SM2CipherFormat.C1C2C3);
            byte[] c1c2c3_bytes = Convert.FromBase64String(c1c2c3_base64);
            Console.WriteLine($"C1C2C3 (BouncyCastle) 密文 (Base64): {c1c2c3_base64}");

            // 2. C1C2C3 -> C1C3C2
            byte[] c1c3c2_bytes = SM2Util.C1C2C3ToC1C3C2(c1c2c3_bytes);
            Console.WriteLine($"转换为 C1C3C2 (国密标准) 密文 (Base64): {Convert.ToBase64String(c1c3c2_bytes)}");

            // 3. C1C3C2 -> C1C2C3
            byte[] roundtrip_c1c2c3_bytes = SM2Util.C1C3C2ToC1C2C3(c1c3c2_bytes);
            Console.WriteLine($"C1C3C2转换回 C1C2C3 密文 (Base64): {Convert.ToBase64String(roundtrip_c1c2c3_bytes)}");
            Console.WriteLine($"C1C3C2往返转换验证: {(c1c2c3_bytes.SequenceEqual(roundtrip_c1c2c3_bytes) ? "成功" : "失败")}");

            // 4. C1C2C3 -> ASN.1
            byte[] asn1_bytes = SM2Util.C1C2C3ToAsn1(c1c2c3_bytes);
            Console.WriteLine($"转换为 ASN.1 密文 (Base64): {Convert.ToBase64String(asn1_bytes)}");

            // 5. ASN.1 -> C1C2C3
            byte[] roundtrip_c1c2c3_from_asn1_bytes = SM2Util.Asn1ToC1C2C3(asn1_bytes);
            Console.WriteLine($"ASN.1转换回 C1C2C3 密文 (Base64): {Convert.ToBase64String(roundtrip_c1c2c3_from_asn1_bytes)}");
            Console.WriteLine($"ASN.1往返转换验证: {(c1c2c3_bytes.SequenceEqual(roundtrip_c1c2c3_from_asn1_bytes) ? "成功" : "失败")}");

            #endregion

            #region 签名格式转换测试 (ASN.1 <-> RS) - 增强版
            Console.WriteLine("\n--------------SM2签名格式转换测试 (Java兼容性)---------------");
            
            // 使用同一个ASN.1签名进行转换测试
            byte[] asn1_sig_bytes = Hex.Decode(sign_ASN1);
            
            // 验证ASN.1签名格式有效性
            bool asn1Valid = SM2Util.IsValidAsn1Signature(asn1_sig_bytes);
            Console.WriteLine($"ASN.1 签名格式验证: {(asn1Valid ? "有效" : "无效")}");

            // 1. ASN.1 -> RS (字节数组方式)
            byte[] converted_rs_bytes = SM2Util.ConvertAsn1ToRs(asn1_sig_bytes);
            byte[] expected_rs_bytes = Hex.Decode(sign_RS);
            Console.WriteLine($"ASN.1 -> RS 转换验证: {(expected_rs_bytes.SequenceEqual(converted_rs_bytes) ? "成功" : "失败")}");

            // 验证RS签名格式有效性
            bool rsValid = SM2Util.IsValidRsSignature(converted_rs_bytes);
            Console.WriteLine($"RS 签名格式验证: {(rsValid ? "有效" : "无效")}");

            // 2. RS -> ASN.1 (字节数组方式)
            byte[] converted_asn1_bytes = SM2Util.ConvertRsToAsn1(converted_rs_bytes);
            Console.WriteLine($"RS -> ASN.1 转换验证: {(asn1_sig_bytes.SequenceEqual(converted_asn1_bytes) ? "成功" : "失败")}");

            // 3. 16进制字符串格式转换测试 (便于与Java互转)
            string hexAsn1FromRs = SM2Util.ConvertHexRsToHexAsn1(sign_RS);
            string hexRsFromAsn1 = SM2Util.ConvertHexAsn1ToHexRs(sign_ASN1);
            
            Console.WriteLine($"原始 ASN.1 签名: {sign_ASN1}");
            Console.WriteLine($"原始 RS 签名: {sign_RS}");
            Console.WriteLine($"RS -> ASN.1 转换结果: {hexAsn1FromRs}");
            Console.WriteLine($"ASN.1 -> RS 转换结果: {hexRsFromAsn1}");
            
            Console.WriteLine($"Hex格式转换验证 (RS): {(sign_RS.Equals(hexRsFromAsn1, StringComparison.OrdinalIgnoreCase) ? "成功" : "失败")}");
            Console.WriteLine($"Hex格式转换验证 (ASN.1): {(sign_ASN1.Equals(hexAsn1FromRs, StringComparison.OrdinalIgnoreCase) ? "成功" : "失败")}");

            // 4. 跨格式验签测试 (确保转换后的签名仍然有效)
            bool rsFromAsn1Valid = SM2Util.VerifySm3WithSm2(plainTextBytes, hexRsFromAsn1, publicKey, SM2Util.SM2SignatureFormat.RS);
            bool asn1FromRsValid = SM2Util.VerifySm3WithSm2(plainTextBytes, hexAsn1FromRs, publicKey, SM2Util.SM2SignatureFormat.ASN1);
            
            Console.WriteLine($"转换后的RS签名验签: {(rsFromAsn1Valid ? "有效" : "无效")}");
            Console.WriteLine($"转换后的ASN.1签名验签: {(asn1FromRsValid ? "有效" : "无效")}");

            // 5. 详细调试信息
            if (!sign_RS.Equals(hexRsFromAsn1, StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine($"调试信息:");
                Console.WriteLine($"  原始RS长度: {sign_RS.Length}");
                Console.WriteLine($"  转换RS长度: {hexRsFromAsn1.Length}");
                Console.WriteLine($"  原始ASN.1长度: {sign_ASN1.Length}");
                Console.WriteLine($"  转换ASN.1长度: {hexAsn1FromRs.Length}");
            }

            // 6. Java兼容性提示
            Console.WriteLine("\n--- Java兼容性说明 ---");
            Console.WriteLine("1. 密钥格式：使用Hex格式可直接与Java BigInteger互转");
            Console.WriteLine("2. RS格式：与Java的 r.toByteArray() + s.toByteArray() 兼容");
            Console.WriteLine("3. ASN.1格式：与Java的 Signature.sign() 默认输出兼容");
            Console.WriteLine("4. 测试时请确保Java端使用相同的密钥和明文");
            Console.WriteLine("5. 注意：相同数据每次签名结果不同是正常的（包含随机数）");

            #endregion
        }

        public static void SM3Test()
        {
            Console.WriteLine("\n--------------国密SM3哈希算法测试---------------");
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

            Console.WriteLine("\n--------------国密SM4对称加密算法测试---------------");
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
