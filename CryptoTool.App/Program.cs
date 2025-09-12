using CryptoTool.Common.Enums;
using CryptoTool.Common.Providers;
using CryptoTool.Common.Providers.GM;
using CryptoTool.Common.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace CryptoTool.App
{
    class Program
    {
        static void Main(string[] args)
        {
            //MedicareTest();
            //AliyunCSBTest();
            MD5Test();
            RSATest();
            AESTest();
            DESTest();

            SM2Test();
            SM3Test();
            SM4Test();
        }
        #region 医保测试

        public static void MedicareTest()
        {
            Console.WriteLine("\n--------------医保MedicareUtil测试---------------");

            string appId = "43AF047BBA47FC8A1AE8EFB2XXXXXXXX";
            string appSecret = "4117E877F5FA0A0188891283E4B617D5";
            long timeStamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            // 生成一对SM2密钥用于签名/验签
            var keyPair = SM2Provider.GenerateKeyPair();
            var publicKey = (Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters)keyPair.Public;
            var privateKey = (Org.BouncyCastle.Crypto.Parameters.ECPrivateKeyParameters)keyPair.Private;

            // 业务data对象（示例）
            var data = new Dictionary<string, object>
            {
                { "appId", appId },
                { "appUserId", "o8z4C5avQXqC0aWFPf1Mzu6D7xxxx" },
                { "idNo", "350582xxxxxxxx3519" },
                { "idType", "01" },
                { "phoneNumber", "137xxxxx033" },
                { "userName", "测试" }
            };

            // 请求报文（未加密前）
            var request = new Dictionary<string, object>
            {
                { "appId", appId },
                { "data", data },
                { "encType", "SM4" },
                { "signType", "SM2" },
                { "timestamp", timeStamp.ToString() },
                { "version", "2.0.1" }
            };

            // 计算签名（Base64）
            string signData = MedicareUtil.SignParameters(request, privateKey, appSecret);
            request["signData"] = signData;

            Console.WriteLine($"入参签名结果signData(Base64): {signData}");

            // 加密data到encData，并清空data
            string encData = MedicareUtil.EncryptData(request, appId, appSecret);
            Console.WriteLine($"入参encData字段加密结果: {encData}");

            // 模拟返回报文（服务端返回相同encData，并附带签名）
            var response = new Dictionary<string, object>
            {
                { "appId", appId },
                { "encData", encData },
                { "encType", "SM4" },
                { "code", "0" },
                { "message", "成功" },
                { "signType", "SM2" },
                { "signData", signData },
                { "timestamp", timeStamp.ToString() },
                { "success", true },
                { "version", "2.0.1" }
            };

            // 服务端对响应参数签名（不含signData/encData/extra）
            string respSign = MedicareUtil.SignParameters(response, privateKey, appSecret);
            Console.WriteLine($"返参签名结果signData(Base64): {respSign}");
            response["signData"] = respSign;

            // 客户端验签
            bool verifyOk = MedicareUtil.VerifyParametersSignature(response, respSign, publicKey, appSecret);
            Console.WriteLine($"返参验签: {(verifyOk ? "通过" : "不通过")}");

            // 解密encData到data
            string decData = MedicareUtil.DecryptEncData(response["encData"].ToString(), appId, appSecret);
            Console.WriteLine($"返参encData字段加密结果: {response["encData"]}");
            Console.WriteLine($"返参encData字段解密结果: {decData}");

            Console.WriteLine("--------------医保MedicareUtil测试完成---------------\n");
        }

        #endregion

        public static void AliyunCSBTest()
        {
            Console.WriteLine("--------------阿里云CSB签名测试---------------");
            string apiName = "testService";
            string apiVersion = "1.0.0";
            long timeStamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            string accessKey = "your_access_key";
            string secretKey = "your_secret_key";
            var formParams = new Dictionary<string, object[]>
            {
                { "param1", new object[] { "value1" } },
                { "param2", new object[] { "value2", "value3" } }
            };
            string body = "{\"data\":\"test\"}";
            string signature = AliyunCSBUtil.Sign(apiName, apiVersion, timeStamp, accessKey, secretKey, formParams, body);
            Console.WriteLine($"生成的签名: {signature}");
            Console.WriteLine("--------------阿里云CSB签名测试完成---------------");
        }

        #region MD5测试

        public static void MD5Test()
        {
            Console.WriteLine("\n--------------MD5哈希测试---------------");

            var md5Provider = new MD5Provider();
            string testData = "Hello, 世界! 这是一个MD5测试数据。";

            try
            {
                // 测试字符串哈希
                Console.WriteLine($"原始数据: {testData}");

                string hexHash = md5Provider.ComputeHash(testData, OutputFormat.Hex);
                Console.WriteLine($"MD5哈希值(Hex): {hexHash}");

                string base64Hash = md5Provider.ComputeHash(testData, OutputFormat.Base64);
                Console.WriteLine($"MD5哈希值(Base64): {base64Hash}");

                // 测试字节数组哈希
                byte[] dataBytes = Encoding.UTF8.GetBytes(testData);
                string byteHash = md5Provider.ComputeHash(dataBytes, OutputFormat.Hex);
                Console.WriteLine($"字节数组MD5哈希值: {byteHash}");

                // 测试哈希验证
                bool isValid = md5Provider.VerifyHash(testData, hexHash, InputFormat.Hex);
                Console.WriteLine($"哈希验证结果: {(isValid ? "通过" : "失败")}");

                // 测试不同编码
                string asciiData = "Hello World";
                string asciiHash = md5Provider.ComputeHash(asciiData, OutputFormat.Hex);
                Console.WriteLine($"ASCII数据: {asciiData}");
                Console.WriteLine($"ASCII MD5哈希值: {asciiHash}");

                // 测试空字符串
                try
                {
                    md5Provider.ComputeHash("", OutputFormat.Hex);
                }
                catch (ArgumentException ex)
                {
                    Console.WriteLine($"空字符串测试: {ex.Message}");
                }

                Console.WriteLine("--------------MD5哈希测试完成---------------\n");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"MD5测试出错: {ex.Message}");
            }
        }

        #endregion

        #region RSA测试

        public static void RSATest()
        {
            Console.WriteLine("\n--------------RSA加密解密测试---------------");

            try
            {
                var rsaProvider = new RSAProvider();
                string testData = "Hello, 世界! 这是一个RSA测试数据。";

                // 生成密钥对
                Console.WriteLine("正在生成RSA密钥对...");
                var keyPair = rsaProvider.GenerateKeyPair(KeySize.Key2048);
                Console.WriteLine($"公钥长度: {keyPair.PublicKey.Length}");
                Console.WriteLine($"私钥长度: {keyPair.PrivateKey.Length}");

                // 测试加密解密
                Console.WriteLine($"原始数据: {testData}");

                string encrypted = rsaProvider.Encrypt(testData, keyPair.PublicKey, OutputFormat.Base64);
                Console.WriteLine($"加密结果(Base64): {encrypted}");

                string decrypted = rsaProvider.Decrypt(encrypted, keyPair.PrivateKey, InputFormat.Base64);
                Console.WriteLine($"解密结果: {decrypted}");
                Console.WriteLine($"加密解密验证: {(testData == decrypted ? "成功" : "失败")}");

                // 测试签名验签
                Console.WriteLine("\n--- RSA签名验签测试 ---");
                string signature = rsaProvider.Sign(testData, keyPair.PrivateKey, SignatureAlgorithm.SHA256withRSA, OutputFormat.Base64);
                Console.WriteLine($"签名结果(Base64): {signature}");

                bool verifyResult = rsaProvider.Verify(testData, signature, keyPair.PublicKey, SignatureAlgorithm.SHA256withRSA, InputFormat.Base64);
                Console.WriteLine($"验签结果: {(verifyResult ? "成功" : "失败")}");

                // 测试不同签名算法
                Console.WriteLine("\n--- 不同签名算法测试 ---");
                var algorithms = new[] { SignatureAlgorithm.SHA1withRSA, SignatureAlgorithm.SHA256withRSA, SignatureAlgorithm.SHA384withRSA, SignatureAlgorithm.SHA512withRSA };

                foreach (var algorithm in algorithms)
                {
                    string sig = rsaProvider.Sign(testData, keyPair.PrivateKey, algorithm, OutputFormat.Hex);
                    bool verify = rsaProvider.Verify(testData, sig, keyPair.PublicKey, algorithm, InputFormat.Hex);
                    Console.WriteLine($"{algorithm}: {(verify ? "成功" : "失败")}");
                }

                // 测试密钥格式转换
                Console.WriteLine("\n--- 密钥格式转换测试 ---");
                var keyPairInternal = rsaProvider.GenerateKeyPairInternal(KeySize.Key2048, OutputFormat.PEM);
                Console.WriteLine("PEM格式密钥对生成成功");

                Console.WriteLine("--------------RSA加密解密测试完成---------------\n");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"RSA测试出错: {ex.Message}");
            }
        }

        #endregion

        #region AES测试

        public static void AESTest()
        {
            Console.WriteLine("\n--------------AES加密解密测试---------------");

            try
            {
                var aesProvider = new AESProvider();
                string testData = "Hello, 世界! 这是一个AES测试数据。";
                string key = aesProvider.GenerateKey(KeySize.Key256);
                string iv = aesProvider.GenerateIV();

                Console.WriteLine($"原始数据: {testData}");
                Console.WriteLine($"密钥(Base64): {key}");
                Console.WriteLine($"IV(Base64): {iv}");

                // 测试CBC模式
                Console.WriteLine("\n--- CBC模式测试 ---");
                string encryptedCBC = aesProvider.Encrypt(testData, key, CryptoMode.CBC, CryptoPaddingMode.PKCS7, OutputFormat.Base64, iv);
                Console.WriteLine($"CBC加密结果: {encryptedCBC}");

                string decryptedCBC = aesProvider.Decrypt(encryptedCBC, key, CryptoMode.CBC, CryptoPaddingMode.PKCS7, InputFormat.Base64, iv);
                Console.WriteLine($"CBC解密结果: {decryptedCBC}");
                Console.WriteLine($"CBC模式验证: {(testData == decryptedCBC ? "成功" : "失败")}");

                // 测试ECB模式
                Console.WriteLine("\n--- ECB模式测试 ---");
                string encryptedECB = aesProvider.Encrypt(testData, key, CryptoMode.ECB, CryptoPaddingMode.PKCS7, OutputFormat.Base64);
                Console.WriteLine($"ECB加密结果: {encryptedECB}");

                string decryptedECB = aesProvider.Decrypt(encryptedECB, key, CryptoMode.ECB, CryptoPaddingMode.PKCS7, InputFormat.Base64);
                Console.WriteLine($"ECB解密结果: {decryptedECB}");
                Console.WriteLine($"ECB模式验证: {(testData == decryptedECB ? "成功" : "失败")}");

                // 测试不同填充模式
                Console.WriteLine("\n--- 不同填充模式测试 ---");
                var paddingModes = new[] { CryptoPaddingMode.PKCS7, CryptoPaddingMode.Zeros, CryptoPaddingMode.None };

                foreach (var padding in paddingModes)
                {
                    try
                    {
                        string enc = aesProvider.Encrypt(testData, key, CryptoMode.CBC, padding, OutputFormat.Hex, iv);
                        string dec = aesProvider.Decrypt(enc, key, CryptoMode.CBC, padding, InputFormat.Hex, iv);
                        Console.WriteLine($"{padding}: {(testData == dec ? "成功" : "失败")}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"{padding}: 失败 - {ex.Message}");
                    }
                }

                // 测试不同密钥长度
                Console.WriteLine("\n--- 不同密钥长度测试 ---");
                var keySizes = new[] { KeySize.Key128, KeySize.Key192, KeySize.Key256 };

                foreach (var keySize in keySizes)
                {
                    string testKey = aesProvider.GenerateKey(keySize);
                    string enc = aesProvider.Encrypt(testData, testKey, CryptoMode.CBC, CryptoPaddingMode.PKCS7, OutputFormat.Base64, iv);
                    string dec = aesProvider.Decrypt(enc, testKey, CryptoMode.CBC, CryptoPaddingMode.PKCS7, InputFormat.Base64, iv);
                    Console.WriteLine($"{keySize}: {(testData == dec ? "成功" : "失败")}");
                }

                // 测试文件加密（创建临时文件）
                Console.WriteLine("\n--- 文件加密测试 ---");
                string tempFile = Path.GetTempFileName();
                string encryptedFile = tempFile + ".enc";
                string decryptedFile = tempFile + ".dec";

                try
                {
                    File.WriteAllText(tempFile, testData, Encoding.UTF8);
                    aesProvider.EncryptFile(tempFile, encryptedFile, key, CryptoMode.CBC, CryptoPaddingMode.PKCS7, iv);
                    aesProvider.DecryptFile(encryptedFile, decryptedFile, key, CryptoMode.CBC, CryptoPaddingMode.PKCS7, iv);

                    string decryptedFileContent = File.ReadAllText(decryptedFile, Encoding.UTF8);
                    Console.WriteLine($"文件加密解密验证: {(testData == decryptedFileContent ? "成功" : "失败")}");
                }
                finally
                {
                    // 清理临时文件
                    if (File.Exists(tempFile)) File.Delete(tempFile);
                    if (File.Exists(encryptedFile)) File.Delete(encryptedFile);
                    if (File.Exists(decryptedFile)) File.Delete(decryptedFile);
                }

                Console.WriteLine("--------------AES加密解密测试完成---------------\n");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"AES测试出错: {ex.Message}");
            }
        }

        #endregion

        #region DES测试

        public static void DESTest()
        {
            Console.WriteLine("\n--------------DES加密解密测试---------------");

            try
            {
                var desProvider = new DESProvider();
                string testData = "Hello, 世界! 这是一个DES测试数据。";
                string key = desProvider.GenerateKey(KeySize.Key64, OutputFormat.Base64);
                string iv = desProvider.GenerateIV(OutputFormat.Base64);

                Console.WriteLine($"原始数据: {testData}");
                Console.WriteLine($"密钥(Base64): {key}");
                Console.WriteLine($"IV(Base64): {iv}");

                // 测试CBC模式
                Console.WriteLine("\n--- CBC模式测试 ---");
                string encryptedCBC = desProvider.Encrypt(testData, key, CryptoMode.CBC, CryptoPaddingMode.PKCS7, OutputFormat.Base64, iv);
                Console.WriteLine($"CBC加密结果: {encryptedCBC}");

                string decryptedCBC = desProvider.Decrypt(encryptedCBC, key, CryptoMode.CBC, CryptoPaddingMode.PKCS7, InputFormat.Base64, iv);
                Console.WriteLine($"CBC解密结果: {decryptedCBC}");
                Console.WriteLine($"CBC模式验证: {(testData == decryptedCBC ? "成功" : "失败")}");

                // 测试ECB模式
                Console.WriteLine("\n--- ECB模式测试 ---");
                string encryptedECB = desProvider.Encrypt(testData, key, CryptoMode.ECB, CryptoPaddingMode.PKCS7, OutputFormat.Base64);
                Console.WriteLine($"ECB加密结果: {encryptedECB}");

                string decryptedECB = desProvider.Decrypt(encryptedECB, key, CryptoMode.ECB, CryptoPaddingMode.PKCS7, InputFormat.Base64);
                Console.WriteLine($"ECB解密结果: {decryptedECB}");
                Console.WriteLine($"ECB模式验证: {(testData == decryptedECB ? "成功" : "失败")}");

                // 测试不同填充模式
                Console.WriteLine("\n--- 不同填充模式测试 ---");
                var paddingModes = new[] { CryptoPaddingMode.PKCS7, CryptoPaddingMode.Zeros, CryptoPaddingMode.None };

                foreach (var padding in paddingModes)
                {
                    try
                    {
                        string enc = desProvider.Encrypt(testData, key, CryptoMode.CBC, padding, OutputFormat.Hex, iv);
                        string dec = desProvider.Decrypt(enc, key, CryptoMode.CBC, padding, InputFormat.Hex, iv);
                        Console.WriteLine($"{padding}: {(testData == dec ? "成功" : "失败")}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"{padding}: 失败 - {ex.Message}");
                    }
                }

                // 测试不同输出格式
                Console.WriteLine("\n--- 不同输出格式测试 ---");
                string encryptedHex = desProvider.Encrypt(testData, key, CryptoMode.CBC, CryptoPaddingMode.PKCS7, OutputFormat.Hex, iv);
                Console.WriteLine($"Hex格式加密: {encryptedHex}");

                string decryptedHex = desProvider.Decrypt(encryptedHex, key, CryptoMode.CBC, CryptoPaddingMode.PKCS7, InputFormat.Hex, iv);
                Console.WriteLine($"Hex格式解密验证: {(testData == decryptedHex ? "成功" : "失败")}");

                // 测试文件加密（创建临时文件）
                Console.WriteLine("\n--- 文件加密测试 ---");
                string tempFile = Path.GetTempFileName();
                string encryptedFile = tempFile + ".enc";
                string decryptedFile = tempFile + ".dec";

                try
                {
                    File.WriteAllText(tempFile, testData, Encoding.UTF8);
                    desProvider.EncryptFile(tempFile, encryptedFile, key, CryptoMode.CBC, CryptoPaddingMode.PKCS7, iv);
                    desProvider.DecryptFile(encryptedFile, decryptedFile, key, CryptoMode.CBC, CryptoPaddingMode.PKCS7, iv);

                    string decryptedFileContent = File.ReadAllText(decryptedFile, Encoding.UTF8);
                    Console.WriteLine($"文件加密解密验证: {(testData == decryptedFileContent ? "成功" : "失败")}");
                }
                finally
                {
                    // 清理临时文件
                    if (File.Exists(tempFile)) File.Delete(tempFile);
                    if (File.Exists(encryptedFile)) File.Delete(encryptedFile);
                    if (File.Exists(decryptedFile)) File.Delete(decryptedFile);
                }

                Console.WriteLine("--------------DES加密解密测试完成---------------\n");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"DES测试出错: {ex.Message}");
            }
        }

        #endregion

        #region SM2测试

        public static void SM2Test()
        {
            Console.WriteLine("\n--------------SM2国密算法测试---------------");

            try
            {
                var sm2Provider = new SM2Provider();
                string testData = "Hello, 世界! 这是一个SM2测试数据。";

                // 生成密钥对
                Console.WriteLine("正在生成SM2密钥对...");
                var keyPair = sm2Provider.GenerateKeyPair(KeySize.Key2048);
                Console.WriteLine($"公钥长度: {keyPair.PublicKey.Length}");
                Console.WriteLine($"私钥长度: {keyPair.PrivateKey.Length}");

                // 测试加密解密
                Console.WriteLine($"原始数据: {testData}");

                string encrypted = sm2Provider.Encrypt(testData, keyPair.PublicKey, OutputFormat.Base64);
                Console.WriteLine($"加密结果(Base64): {encrypted}");

                string decrypted = sm2Provider.Decrypt(encrypted, keyPair.PrivateKey, InputFormat.Base64);
                Console.WriteLine($"解密结果: {decrypted}");
                Console.WriteLine($"加密解密验证: {(testData == decrypted ? "成功" : "失败")}");

                // 测试签名验签
                Console.WriteLine("\n--- SM2签名验签测试 ---");
                string signature = sm2Provider.Sign(testData, keyPair.PrivateKey, SignatureAlgorithm.SM3withSM2, OutputFormat.Base64);
                Console.WriteLine($"签名结果(Base64): {signature}");

                bool verifyResult = sm2Provider.Verify(testData, signature, keyPair.PublicKey, SignatureAlgorithm.SM3withSM2, InputFormat.Base64);
                Console.WriteLine($"验签结果: {(verifyResult ? "成功" : "失败")}");

                // 测试不同密文格式
                Console.WriteLine("\n--- 不同密文格式测试 ---");
                var cipherFormats = new[] { SM2Provider.SM2CipherFormat.C1C2C3, SM2Provider.SM2CipherFormat.C1C3C2, SM2Provider.SM2CipherFormat.ASN1 };

                foreach (var format in cipherFormats)
                {
                    try
                    {
                        // 使用内部方法测试不同格式
                        var keyPairInternal1 = sm2Provider.GenerateKeyPairInternal(KeySize.Key256, OutputFormat.Base64);
                        var publicKeyObj1 = SM2Provider.ParsePublicKeyFromBase64(keyPairInternal1.publicKey);
                        var privateKeyObj1 = SM2Provider.ParsePrivateKeyFromBase64(keyPairInternal1.privateKey);

                        byte[] dataBytes = Encoding.UTF8.GetBytes(testData);
                        byte[] encryptedBytes = SM2Provider.Encrypt(dataBytes, publicKeyObj1, format);
                        byte[] decryptedBytes = SM2Provider.Decrypt(encryptedBytes, privateKeyObj1, format);

                        string decryptedText = Encoding.UTF8.GetString(decryptedBytes);
                        Console.WriteLine($"{format}: {(testData == decryptedText ? "成功" : "失败")}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"{format}: 失败 - {ex.Message}");
                    }
                }

                // 测试不同签名格式
                Console.WriteLine("\n--- 不同签名格式测试 ---");
                var signatureFormats = new[] { SM2Provider.SM2SignatureFormat.ASN1, SM2Provider.SM2SignatureFormat.RS };

                foreach (var format in signatureFormats)
                {
                    try
                    {
                        var keyPairInternal2 = sm2Provider.GenerateKeyPairInternal(KeySize.Key256, OutputFormat.Base64);
                        var publicKeyObj2 = SM2Provider.ParsePublicKeyFromBase64(keyPairInternal2.publicKey);
                        var privateKeyObj2 = SM2Provider.ParsePrivateKeyFromBase64(keyPairInternal2.privateKey);

                        byte[] dataBytes = Encoding.UTF8.GetBytes(testData);
                        byte[] signatureBytes = SM2Provider.Sign(dataBytes, privateKeyObj2, format);
                        bool verify = SM2Provider.Verify(dataBytes, signatureBytes, publicKeyObj2, format);

                        Console.WriteLine($"{format}: {(verify ? "成功" : "失败")}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"{format}: 失败 - {ex.Message}");
                    }
                }

                // 测试密钥格式转换
                Console.WriteLine("\n--- 密钥格式转换测试 ---");
                var keyPairInternal3 = sm2Provider.GenerateKeyPairInternal(KeySize.Key256, OutputFormat.Base64);
                var publicKeyObj3 = SM2Provider.ParsePublicKeyFromBase64(keyPairInternal3.publicKey);
                var privateKeyObj3 = SM2Provider.ParsePrivateKeyFromBase64(keyPairInternal3.privateKey);

                string rawPublicKey = SM2Provider.PublicKeyToRawBase64(publicKeyObj3, false);
                string rawPrivateKey = SM2Provider.PrivateKeyToRawBase64(privateKeyObj3);
                Console.WriteLine($"原始公钥格式: {rawPublicKey}");
                Console.WriteLine($"原始私钥格式: {rawPrivateKey}");

                Console.WriteLine("--------------SM2国密算法测试完成---------------\n");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"SM2测试出错: {ex.Message}");
            }
        }

        #endregion

        #region SM3测试

        public static void SM3Test()
        {
            Console.WriteLine("\n--------------SM3国密哈希测试---------------");

            try
            {
                var sm3Provider = new SM3Provider();
                string testData = "Hello, 世界! 这是一个SM3测试数据。";

                // 测试字符串哈希
                Console.WriteLine($"原始数据: {testData}");

                string hexHash = sm3Provider.ComputeHash(testData, OutputFormat.Hex);
                Console.WriteLine($"SM3哈希值(Hex): {hexHash}");

                string base64Hash = sm3Provider.ComputeHash(testData, OutputFormat.Base64);
                Console.WriteLine($"SM3哈希值(Base64): {base64Hash}");

                // 测试字节数组哈希
                byte[] dataBytes = Encoding.UTF8.GetBytes(testData);
                string byteHash = sm3Provider.ComputeHash(dataBytes, OutputFormat.Hex);
                Console.WriteLine($"字节数组SM3哈希值: {byteHash}");

                // 测试哈希验证
                bool isValid = sm3Provider.VerifyHash(testData, hexHash, InputFormat.Hex);
                Console.WriteLine($"哈希验证结果: {(isValid ? "通过" : "失败")}");

                // 测试HMAC-SM3
                Console.WriteLine("\n--- HMAC-SM3测试 ---");
                string hmacKey = "test_hmac_key_12345";
                string hmacResult = sm3Provider.ComputeHMac(testData, hmacKey, OutputFormat.Hex);
                Console.WriteLine($"HMAC-SM3结果: {hmacResult}");

                // 测试不同编码
                string asciiData = "Hello World";
                string asciiHash = sm3Provider.ComputeHash(asciiData, OutputFormat.Hex);
                Console.WriteLine($"ASCII数据: {asciiData}");
                Console.WriteLine($"ASCII SM3哈希值: {asciiHash}");

                // 测试空字符串
                try
                {
                    sm3Provider.ComputeHash("", OutputFormat.Hex);
                }
                catch (ArgumentException ex)
                {
                    Console.WriteLine($"空字符串测试: {ex.Message}");
                }

                // 测试文件哈希（创建临时文件）
                Console.WriteLine("\n--- 文件哈希测试 ---");
                string tempFile = Path.GetTempFileName();
                try
                {
                    File.WriteAllText(tempFile, testData, Encoding.UTF8);
                    string fileHash = sm3Provider.ComputeFileHash(tempFile, OutputFormat.Hex);
                    Console.WriteLine($"文件SM3哈希值: {fileHash}");
                    Console.WriteLine($"文件哈希验证: {(fileHash == hexHash ? "成功" : "失败")}");
                }
                finally
                {
                    if (File.Exists(tempFile)) File.Delete(tempFile);
                }

                // 测试流哈希
                Console.WriteLine("\n--- 流哈希测试 ---");
                using (var stream = new MemoryStream(Encoding.UTF8.GetBytes(testData)))
                {
                    string streamHash = sm3Provider.ComputeStreamHash(stream, OutputFormat.Hex);
                    Console.WriteLine($"流SM3哈希值: {streamHash}");
                    Console.WriteLine($"流哈希验证: {(streamHash == hexHash ? "成功" : "失败")}");
                }

                Console.WriteLine("--------------SM3国密哈希测试完成---------------\n");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"SM3测试出错: {ex.Message}");
            }
        }

        #endregion

        #region SM4测试

        public static void SM4Test()
        {
            Console.WriteLine("\n--------------SM4国密算法测试---------------");

            try
            {
                var sm4Provider = new SM4Provider();
                string testData = "Hello, 世界! 这是一个SM4测试数据。";
                string key = sm4Provider.GenerateKey(KeySize.Key128, OutputFormat.Base64);
                string iv = sm4Provider.GenerateIV(OutputFormat.Base64);

                Console.WriteLine($"原始数据: {testData}");
                Console.WriteLine($"密钥(Base64): {key}");
                Console.WriteLine($"IV(Base64): {iv}");

                // 测试CBC模式
                Console.WriteLine("\n--- CBC模式测试 ---");
                string encryptedCBC = sm4Provider.Encrypt(testData, key, CryptoMode.CBC, CryptoPaddingMode.PKCS7, OutputFormat.Base64, iv);
                Console.WriteLine($"CBC加密结果: {encryptedCBC}");

                string decryptedCBC = sm4Provider.Decrypt(encryptedCBC, key, CryptoMode.CBC, CryptoPaddingMode.PKCS7, InputFormat.Base64, iv);
                Console.WriteLine($"CBC解密结果: {decryptedCBC}");
                Console.WriteLine($"CBC模式验证: {(testData == decryptedCBC ? "成功" : "失败")}");

                // 测试ECB模式
                Console.WriteLine("\n--- ECB模式测试 ---");
                string encryptedECB = sm4Provider.Encrypt(testData, key, CryptoMode.ECB, CryptoPaddingMode.PKCS7, OutputFormat.Base64);
                Console.WriteLine($"ECB加密结果: {encryptedECB}");

                string decryptedECB = sm4Provider.Decrypt(encryptedECB, key, CryptoMode.ECB, CryptoPaddingMode.PKCS7, InputFormat.Base64);
                Console.WriteLine($"ECB解密结果: {decryptedECB}");
                Console.WriteLine($"ECB模式验证: {(testData == decryptedECB ? "成功" : "失败")}");

                // 测试CFB模式
                Console.WriteLine("\n--- CFB模式测试 ---");
                string encryptedCFB = sm4Provider.Encrypt(testData, key, CryptoMode.CFB, CryptoPaddingMode.PKCS7, OutputFormat.Base64, iv);
                Console.WriteLine($"CFB加密结果: {encryptedCFB}");

                string decryptedCFB = sm4Provider.Decrypt(encryptedCFB, key, CryptoMode.CFB, CryptoPaddingMode.PKCS7, InputFormat.Base64, iv);
                Console.WriteLine($"CFB解密结果: {decryptedCFB}");
                Console.WriteLine($"CFB模式验证: {(testData == decryptedCFB ? "成功" : "失败")}");

                // 测试OFB模式
                Console.WriteLine("\n--- OFB模式测试 ---");
                string encryptedOFB = sm4Provider.Encrypt(testData, key, CryptoMode.OFB, CryptoPaddingMode.PKCS7, OutputFormat.Base64, iv);
                Console.WriteLine($"OFB加密结果: {encryptedOFB}");

                string decryptedOFB = sm4Provider.Decrypt(encryptedOFB, key, CryptoMode.OFB, CryptoPaddingMode.PKCS7, InputFormat.Base64, iv);
                Console.WriteLine($"OFB解密结果: {decryptedOFB}");
                Console.WriteLine($"OFB模式验证: {(testData == decryptedOFB ? "成功" : "失败")}");

                // 测试不同填充模式
                Console.WriteLine("\n--- 不同填充模式测试 ---");
                var paddingModes = new[] { CryptoPaddingMode.PKCS7, CryptoPaddingMode.Zeros, CryptoPaddingMode.None };

                foreach (var padding in paddingModes)
                {
                    try
                    {
                        string enc = sm4Provider.Encrypt(testData, key, CryptoMode.CBC, padding, OutputFormat.Hex, iv);
                        string dec = sm4Provider.Decrypt(enc, key, CryptoMode.CBC, padding, InputFormat.Hex, iv);
                        Console.WriteLine($"{padding}: {(testData == dec ? "成功" : "失败")}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"{padding}: 失败 - {ex.Message}");
                    }
                }

                // 测试不同输出格式
                Console.WriteLine("\n--- 不同输出格式测试 ---");
                string encryptedHex = sm4Provider.Encrypt(testData, key, CryptoMode.CBC, CryptoPaddingMode.PKCS7, OutputFormat.Hex, iv);
                Console.WriteLine($"Hex格式加密: {encryptedHex}");

                string decryptedHex = sm4Provider.Decrypt(encryptedHex, key, CryptoMode.CBC, CryptoPaddingMode.PKCS7, InputFormat.Hex, iv);
                Console.WriteLine($"Hex格式解密验证: {(testData == decryptedHex ? "成功" : "失败")}");

                // 测试静态方法
                Console.WriteLine("\n--- 静态方法测试 ---");
                string staticEncrypted = SM4Provider.EncryptEcb(testData, key);
                string staticDecrypted = SM4Provider.DecryptEcb(staticEncrypted, key);
                Console.WriteLine($"静态方法ECB模式验证: {(testData == staticDecrypted ? "成功" : "失败")}");

                // 测试文件加密（创建临时文件）
                Console.WriteLine("\n--- 文件加密测试 ---");
                string tempFile = Path.GetTempFileName();
                string encryptedFile = tempFile + ".enc";
                string decryptedFile = tempFile + ".dec";

                try
                {
                    File.WriteAllText(tempFile, testData, Encoding.UTF8);
                    sm4Provider.EncryptFile(tempFile, encryptedFile, key, CryptoMode.CBC, CryptoPaddingMode.PKCS7, iv);
                    sm4Provider.DecryptFile(encryptedFile, decryptedFile, key, CryptoMode.CBC, CryptoPaddingMode.PKCS7, iv);

                    string decryptedFileContent = File.ReadAllText(decryptedFile, Encoding.UTF8);
                    Console.WriteLine($"文件加密解密验证: {(testData == decryptedFileContent ? "成功" : "失败")}");
                }
                finally
                {
                    // 清理临时文件
                    if (File.Exists(tempFile)) File.Delete(tempFile);
                    if (File.Exists(encryptedFile)) File.Delete(encryptedFile);
                    if (File.Exists(decryptedFile)) File.Delete(decryptedFile);
                }

                // 测试密钥验证
                Console.WriteLine("\n--- 密钥验证测试 ---");
                bool validKey = sm4Provider.ValidateKey(key, InputFormat.Base64);
                Console.WriteLine($"密钥验证结果: {(validKey ? "有效" : "无效")}");

                Console.WriteLine("--------------SM4国密算法测试完成---------------\n");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"SM4测试出错: {ex.Message}");
            }
        }

        #endregion
    }
}
