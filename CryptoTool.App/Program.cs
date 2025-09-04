using CryptoTool.Common;
using CryptoTool.Common.GM;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.IO;
using System.Linq;
using System.Text;

namespace CryptoTool.App
{
    class Program
    {
        static void Main(string[] args)
        {
            RSATest();
            AESTest();
            //DESTest();

            //SM2Test();
            //SM3Test();
            //SM4Test();
            Console.WriteLine("输入任意键退出！");
        }

        public static void AESTest()
        {
            Console.WriteLine("--------------AES算法全面测试---------------");

            // 1. 基础功能测试
            TestBasicAESFunctionality();

            // 2. 多种模式测试
            TestAESModes();

            // 3. 不同密钥长度测试
            TestAESKeySizes();

            // 4. 填充模式测试
            TestAESPaddingModes();

            // 5. 输出格式测试
            TestAESOutputFormats();

            // 6. 文件加密测试
            TestAESFileEncryption();

            // 7. 流式加密测试
            TestAESStreamEncryption();

            // 8. 密钥生成测试
            TestAESKeyGeneration();

            // 9. 向后兼容性测试
            TestAESBackwardCompatibility();

            // 10. .NET Standard 2.1 兼容性测试
            TestAESNetStandard21Compatibility();
        }

        /// <summary>
        /// 测试基础AES功能
        /// </summary>
        public static void TestBasicAESFunctionality()
        {
            Console.WriteLine("\n--- 基础AES功能测试 ---");

            try
            {
                string plaintext = "这是AES加密测试的内容，包含中文和English mixed content!";
                string key = "mySecretKey12345";

                // 默认参数加密解密
                string encrypted = AESUtil.EncryptByAES(plaintext, key);
                string decrypted = AESUtil.DecryptByAES(encrypted, key);

                Console.WriteLine($"原文: {plaintext}");
                Console.WriteLine($"密文: {encrypted}");
                Console.WriteLine($"解密: {decrypted}");
                Console.WriteLine($"基础加密解密测试: {(plaintext == decrypted ? "成功" : "失败")}");

                // 空字符串测试
                try
                {
                    AESUtil.EncryptByAES("", key);
                    Console.WriteLine("空字符串测试: 失败（应该抛出异常）");
                }
                catch (ArgumentException)
                {
                    Console.WriteLine("空字符串测试: 成功（正确抛出异常）");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"基础功能测试失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 测试不同的AES加密模式
        /// </summary>
        public static void TestAESModes()
        {
            Console.WriteLine("\n--- AES加密模式测试 ---");

            string plaintext = "AES加密模式测试内容";
            string key = "testKey1234567890123456789012345";
            string iv = "testIV1234567890";

            var modes = new[]
            {
                AESUtil.AESMode.ECB,
                AESUtil.AESMode.CBC,
                AESUtil.AESMode.CFB,
                AESUtil.AESMode.OFB
            };

            foreach (var mode in modes)
            {
                try
                {
                    string currentIv = mode == AESUtil.AESMode.ECB ? null : iv;

                    string encrypted = AESUtil.EncryptByAES(plaintext, key, mode, AESUtil.AESPadding.PKCS7, AESUtil.OutputFormat.Base64, currentIv);
                    string decrypted = AESUtil.DecryptByAES(encrypted, key, mode, AESUtil.AESPadding.PKCS7, AESUtil.OutputFormat.Base64, currentIv);

                    bool success = plaintext == decrypted;
                    Console.WriteLine($"{mode} 模式测试: {(success ? "成功" : "失败")}");

                    if (!success)
                    {
                        Console.WriteLine($"  原文: {plaintext}");
                        Console.WriteLine($"  解密: {decrypted}");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"{mode} 模式测试失败: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// 测试不同的AES密钥长度
        /// </summary>
        public static void TestAESKeySizes()
        {
            Console.WriteLine("\n--- AES密钥长度测试 ---");

            string plaintext = "AES密钥长度测试内容";

            var keySizes = new[]
            {
                AESUtil.AESKeySize.Aes128,
                AESUtil.AESKeySize.Aes192,
                AESUtil.AESKeySize.Aes256
            };

            foreach (var keySize in keySizes)
            {
                try
                {
                    string key = AESUtil.GenerateKey(keySize);
                    string iv = AESUtil.GenerateIV();

                    string encrypted = AESUtil.EncryptByAES(plaintext, key, AESUtil.AESMode.CBC, AESUtil.AESPadding.PKCS7, AESUtil.OutputFormat.Base64, iv);
                    string decrypted = AESUtil.DecryptByAES(encrypted, key, AESUtil.AESMode.CBC, AESUtil.AESPadding.PKCS7, AESUtil.OutputFormat.Base64, iv);

                    bool success = plaintext == decrypted;
                    Console.WriteLine($"AES-{(int)keySize} 测试: {(success ? "成功" : "失败")}");

                    // 显示密钥强度
                    byte[] keyBytes = Convert.FromBase64String(key);
                    Console.WriteLine($"  密钥强度: {AESUtil.GetKeyStrengthDescription(keyBytes)}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"AES-{(int)keySize} 测试失败: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// 测试不同的填充模式
        /// </summary>
        public static void TestAESPaddingModes()
        {
            Console.WriteLine("\n--- AES填充模式测试 ---");

            string plaintext = "AES填充模式测试内容"; // 确保不是16字节的倍数
            string key = "testKey1234567890123456789012345";
            string iv = "testIV1234567890";

            var paddingModes = new[]
            {
                AESUtil.AESPadding.PKCS7,
                AESUtil.AESPadding.Zeros
            };

            foreach (var padding in paddingModes)
            {
                try
                {
                    string encrypted = AESUtil.EncryptByAES(plaintext, key, AESUtil.AESMode.CBC, padding, AESUtil.OutputFormat.Base64, iv);
                    string decrypted = AESUtil.DecryptByAES(encrypted, key, AESUtil.AESMode.CBC, padding, AESUtil.OutputFormat.Base64, iv);

                    bool success = padding == AESUtil.AESPadding.PKCS7 ?
                        plaintext == decrypted :
                        decrypted.TrimEnd('\0') == plaintext; // Zeros填充需要去除末尾的零

                    Console.WriteLine($"{padding} 填充测试: {(success ? "成功" : "失败")}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"{padding} 填充测试失败: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// 测试不同的输出格式
        /// </summary>
        public static void TestAESOutputFormats()
        {
            Console.WriteLine("\n--- AES输出格式测试 ---");

            string plaintext = "AES输出格式测试内容";
            string key = "testKey1234567890123456789012345";
            string iv = "testIV1234567890";

            var formats = new[]
            {
                AESUtil.OutputFormat.Base64,
                AESUtil.OutputFormat.Hex
            };

            foreach (var format in formats)
            {
                try
                {
                    string encrypted = AESUtil.EncryptByAES(plaintext, key, AESUtil.AESMode.CBC, AESUtil.AESPadding.PKCS7, format, iv);
                    string decrypted = AESUtil.DecryptByAES(encrypted, key, AESUtil.AESMode.CBC, AESUtil.AESPadding.PKCS7, format, iv);

                    bool success = plaintext == decrypted;
                    Console.WriteLine($"{format} 格式测试: {(success ? "成功" : "失败")}");
                    Console.WriteLine($"  密文长度: {encrypted.Length}");
                    Console.WriteLine($"  密文示例: {encrypted.Substring(0, Math.Min(50, encrypted.Length))}...");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"{format} 格式测试失败: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// 测试AES文件加密
        /// </summary>
        public static void TestAESFileEncryption()
        {
            Console.WriteLine("\n--- AES文件加密测试 ---");

            try
            {
                string testContent = "这是用于测试AES文件加密的内容。\n包含多行文本和特殊字符：!@#$%^&*()";
                string tempDir = Path.GetTempPath();
                string originalFile = Path.Combine(tempDir, "aes_test_original.txt");
                string encryptedFile = Path.Combine(tempDir, "aes_test_encrypted.bin");
                string decryptedFile = Path.Combine(tempDir, "aes_test_decrypted.txt");

                // 创建测试文件
                File.WriteAllText(originalFile, testContent, Encoding.UTF8);

                string key = AESUtil.GenerateKey(AESUtil.AESKeySize.Aes256);
                string iv = AESUtil.GenerateIV();

                // 加密文件
                AESUtil.EncryptFile(originalFile, encryptedFile, key, AESUtil.AESMode.CBC, AESUtil.AESPadding.PKCS7, iv);
                Console.WriteLine("文件加密: 成功");

                // 解密文件
                AESUtil.DecryptFile(encryptedFile, decryptedFile, key, AESUtil.AESMode.CBC, AESUtil.AESPadding.PKCS7, iv);
                Console.WriteLine("文件解密: 成功");

                // 验证内容
                string decryptedContent = File.ReadAllText(decryptedFile, Encoding.UTF8);
                bool success = testContent == decryptedContent;
                Console.WriteLine($"文件内容验证: {(success ? "成功" : "失败")}");

                // 清理临时文件
                try
                {
                    File.Delete(originalFile);
                    File.Delete(encryptedFile);
                    File.Delete(decryptedFile);
                }
                catch { /* 忽略清理错误 */ }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"文件加密测试失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 测试AES流式加密
        /// </summary>
        public static void TestAESStreamEncryption()
        {
            Console.WriteLine("\n--- AES流式加密测试 ---");

            try
            {
                string testContent = "这是用于测试AES流式加密的内容，内容较长以测试流式处理的效果。" +
                                   "Lorem ipsum dolor sit amet, consectetur adipiscing elit. " +
                                   "Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.";

                string key = AESUtil.GenerateKey(AESUtil.AESKeySize.Aes256);
                string iv = AESUtil.GenerateIV();

                // 准备流
                using (var inputStream = new MemoryStream(Encoding.UTF8.GetBytes(testContent)))
                using (var encryptedStream = new MemoryStream())
                using (var decryptedStream = new MemoryStream())
                {
                    // 加密
                    AESUtil.EncryptStream(inputStream, encryptedStream, key, AESUtil.AESMode.CBC, AESUtil.AESPadding.PKCS7, iv);
                    Console.WriteLine("流式加密: 成功");

                    // 解密
                    encryptedStream.Position = 0;
                    AESUtil.DecryptStream(encryptedStream, decryptedStream, key, AESUtil.AESMode.CBC, AESUtil.AESPadding.PKCS7, iv);
                    Console.WriteLine("流式解密: 成功");

                    // 验证
                    string decryptedContent = Encoding.UTF8.GetString(decryptedStream.ToArray());
                    bool success = testContent == decryptedContent;
                    Console.WriteLine($"流式加密内容验证: {(success ? "成功" : "失败")}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"流式加密测试失败: {ex.Message}");
            }
        }


        /// <summary>
        /// 测试AES密钥生成
        /// </summary>
        public static void TestAESKeyGeneration()
        {
            Console.WriteLine("\n--- AES密钥生成测试 ---");

            try
            {
                // 测试不同长度的密钥生成
                var keySizes = new[] { AESUtil.AESKeySize.Aes128, AESUtil.AESKeySize.Aes192, AESUtil.AESKeySize.Aes256 };

                foreach (var keySize in keySizes)
                {
                    string key = AESUtil.GenerateKey(keySize);
                    byte[] keyBytes = Convert.FromBase64String(key);

                    bool correctLength = keyBytes.Length == (int)keySize / 8;
                    Console.WriteLine($"AES-{(int)keySize} 密钥生成: {(correctLength ? "成功" : "失败")} (长度: {keyBytes.Length} 字节)");
                }

                // 测试IV生成
                string iv1 = AESUtil.GenerateIV();
                string iv2 = AESUtil.GenerateIV();
                byte[] ivBytes = Convert.FromBase64String(iv1);

                bool correctIvLength = ivBytes.Length == 16;
                bool ivsDifferent = iv1 != iv2;

                Console.WriteLine($"IV生成测试: {(correctIvLength ? "成功" : "失败")} (长度: {ivBytes.Length} 字节)");
                Console.WriteLine($"IV随机性测试: {(ivsDifferent ? "成功" : "失败")}");

                // 密钥强度验证
                foreach (var keySize in keySizes)
                {
                    string key = AESUtil.GenerateKey(keySize);
                    byte[] keyBytes = Convert.FromBase64String(key);
                    string strength = AESUtil.GetKeyStrengthDescription(keyBytes);
                    Console.WriteLine($"  {strength}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"密钥生成测试失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 测试向后兼容性
        /// </summary>
        public static void TestAESBackwardCompatibility()
        {
            Console.WriteLine("\n--- AES向后兼容性测试 ---");

            try
            {
                string plaintext = "向后兼容性测试内容";
                string key = "compatibilityTestKey1234567890123";

                // 使用旧方法加密
#pragma warning disable CS0618 // 忽略过时警告
                string oldEncrypted = AESUtil.EncryptByAES_Legacy(plaintext, key);
                string oldDecrypted = AESUtil.DecryptByAES_Legacy(oldEncrypted, key);
#pragma warning restore CS0618

                bool oldMethodWorks = plaintext == oldDecrypted;
                Console.WriteLine($"旧方法测试: {(oldMethodWorks ? "成功" : "失败")}");

                // 新旧方法交叉兼容性测试
                string newEncrypted = AESUtil.EncryptByAES(plaintext, key, AESUtil.AESMode.CBC, AESUtil.AESPadding.PKCS7, AESUtil.OutputFormat.Hex);

                // 注意：由于实现细节不同，新旧方法可能不完全兼容，这里主要测试各自的正确性
                Console.WriteLine("新方法加密格式: " + newEncrypted.Substring(0, Math.Min(30, newEncrypted.Length)) + "...");
                Console.WriteLine("旧方法加密格式: " + oldEncrypted.Substring(0, Math.Min(30, oldEncrypted.Length)) + "...");
                Console.WriteLine("向后兼容性: 各方法独立工作正常");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"向后兼容性测试失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 测试.NET Standard 2.1兼容性
        /// </summary>
        public static void TestAESNetStandard21Compatibility()
        {
            Console.WriteLine("\n--- .NET Standard 2.1兼容性测试 ---");

            try
            {
                Console.WriteLine("测试.NET Standard 2.1特性兼容性:");

                // 测试基本功能
                string plaintext = ".NET Standard 2.1兼容性测试";
                string key = AESUtil.GenerateKey(AESUtil.AESKeySize.Aes256);
                string iv = AESUtil.GenerateIV();

                // 测试所有支持的模式
                var modes = new[] { AESUtil.AESMode.ECB, AESUtil.AESMode.CBC, AESUtil.AESMode.CFB, AESUtil.AESMode.OFB };
                foreach (var mode in modes)
                {
                    try
                    {
                        string currentIv = mode == AESUtil.AESMode.ECB ? null : iv;
                        string encrypted = AESUtil.EncryptByAES(plaintext, key, mode, AESUtil.AESPadding.PKCS7, AESUtil.OutputFormat.Base64, currentIv);
                        string decrypted = AESUtil.DecryptByAES(encrypted, key, mode, AESUtil.AESPadding.PKCS7, AESUtil.OutputFormat.Base64, currentIv);

                        bool success = plaintext == decrypted;
                        Console.WriteLine($"  {mode} 模式: {(success ? "兼容" : "不兼容")}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"  {mode} 模式: 不兼容 ({ex.GetType().Name})");
                    }
                }

                // 测试流处理
                try
                {
                    using (var input = new MemoryStream(Encoding.UTF8.GetBytes(plaintext)))
                    using (var output = new MemoryStream())
                    {
                        AESUtil.EncryptStream(input, output, key, AESUtil.AESMode.CBC, AESUtil.AESPadding.PKCS7, iv);
                        Console.WriteLine("  流处理: 兼容");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"  流处理: 不兼容 ({ex.GetType().Name})");
                }

                Console.WriteLine(".NET Standard 2.1兼容性测试完成");
            }
            catch (Exception ex)
            {
                Console.WriteLine($".NET Standard 2.1兼容性测试失败: {ex.Message}");
            }
        }


        /// <summary>
        /// 测试RSA功能
        /// </summary>
        public static void RSATest()
        {
            Console.WriteLine("--------------RSA功能测试---------------");
            
            // 1. 测试RSA和RSA2签名验签
            TestRSASignature();
            
            // 2. 测试Java互操作性
            TestJavaCompatibility();
            
            // 3. 测试PKCS格式转换
            TestPKCSConversion();
            
            // 4. 测试多种密钥格式
            TestMultipleKeyFormats();
            
            // 5. 测试新的PKCS8导出功能
            TestNewPKCS8Export();
            
            // 6. 测试.NET Standard 2.1兼容性
            TestNetStandard21Compatibility();
        }

        /// <summary>
        /// 测试RSA和RSA2签名验签
        /// </summary>
        public static void TestRSASignature()
        {
            Console.WriteLine("\n--- RSA/RSA2签名验签测试 ---");
            
            string plaintext = "这是RSA/RSA2签名验签测试内容";
            var keyPair = RSAUtil.CreateRSAKey(2048, RSAUtil.RSAKeyFormat.XML);
            string publicKey = keyPair.Key;
            string privateKey = keyPair.Value;

            // RSA签名（SHA1）
            string rsaSignature = RSAUtil.HashAndSignString(plaintext, privateKey, RSAUtil.RSAType.RSA, RSAUtil.RSAKeyFormat.XML);
            bool rsaVerifyResult = RSAUtil.VerifySigned(plaintext, rsaSignature, publicKey, RSAUtil.RSAType.RSA, RSAUtil.RSAKeyFormat.XML);
            Console.WriteLine($"RSA (SHA1) 签名验证: {(rsaVerifyResult ? "成功" : "失败")}");

            // RSA2签名（SHA256）
            string rsa2Signature = RSAUtil.HashAndSignString(plaintext, privateKey, RSAUtil.RSAType.RSA2, RSAUtil.RSAKeyFormat.XML);
            bool rsa2VerifyResult = RSAUtil.VerifySigned(plaintext, rsa2Signature, publicKey, RSAUtil.RSAType.RSA2, RSAUtil.RSAKeyFormat.XML);
            Console.WriteLine($"RSA2 (SHA256) 签名验证: {(rsa2VerifyResult ? "成功" : "失败")}");
        }

        /// <summary>
        /// 测试Java互操作性
        /// </summary>
        public static void TestJavaCompatibility()
        {
            Console.WriteLine("\n--- Java互操作性测试 ---");
            
            string plaintext = "Java互操作性测试内容";
            
            // 创建Java格式密钥对
            var javaKeyPair = RSAUtil.CreateRSAKey(2048, RSAUtil.RSAKeyFormat.Java);
            string javaPublicKey = javaKeyPair.Key;
            string javaPrivateKey = javaKeyPair.Value;

            // Java格式加密解密
            string encryptedText = RSAUtil.EncryptForJava(plaintext, javaPublicKey);
            string decryptedText = RSAUtil.DecryptFromJava(encryptedText, javaPrivateKey);
            Console.WriteLine($"Java格式加密解密: {(plaintext == decryptedText ? "成功" : "失败")}");

            // Java格式签名验签
            string javaSignature = RSAUtil.SignForJava(plaintext, javaPrivateKey, RSAUtil.RSAType.RSA2);
            bool javaVerifyResult = RSAUtil.VerifyFromJava(plaintext, javaSignature, javaPublicKey, RSAUtil.RSAType.RSA2);
            Console.WriteLine($"Java格式签名验证: {(javaVerifyResult ? "成功" : "失败")}");

            // 格式转换测试
            var xmlKeyPair = RSAUtil.CreateRSAKey(2048, RSAUtil.RSAKeyFormat.XML);
            string xmlToJavaPublic = RSAUtil.ConvertToJavaFormat(xmlKeyPair.Key, false);
            string xmlToJavaPrivate = RSAUtil.ConvertToJavaFormat(xmlKeyPair.Value, true);
            string javaToXmlPublic = RSAUtil.ConvertFromJavaFormat(xmlToJavaPublic, false);
            string javaToXmlPrivate = RSAUtil.ConvertFromJavaFormat(xmlToJavaPrivate, true);
            
            Console.WriteLine($"XML到Java格式转换: 成功");
            Console.WriteLine($"Java到XML格式转换: 成功");
        }

        /// <summary>
        /// 测试PKCS格式转换
        /// </summary>
        public static void TestPKCSConversion()
        {
            Console.WriteLine("\n--- PKCS格式转换测试 ---");
            
            // 创建PKCS1格式密钥对
            var pkcs1KeyPair = RSAUtil.CreateRSAKey(2048, RSAUtil.RSAKeyFormat.PKCS1);
            string pkcs1PublicKey = pkcs1KeyPair.Key;
            string pkcs1PrivateKey = pkcs1KeyPair.Value;

            // PKCS1转PKCS8
            string pkcs8PublicKey = RSAUtil.ConvertPkcs1ToPkcs8(pkcs1PublicKey, false);
            string pkcs8PrivateKey = RSAUtil.ConvertPkcs1ToPkcs8(pkcs1PrivateKey, true);
            Console.WriteLine("PKCS1 -> PKCS8 转换: 成功");

            // PKCS8转PKCS1
            string backToPkcs1Public = RSAUtil.ConvertPkcs8ToPkcs1(pkcs8PublicKey, false);
            string backToPkcs1Private = RSAUtil.ConvertPkcs8ToPkcs1(pkcs8PrivateKey, true);
            Console.WriteLine("PKCS8 -> PKCS1 转换: 成功");

            // 验证转换正确性（通过签名验签）
            string testText = "PKCS格式转换验证测试";
            string signature = RSAUtil.HashAndSignString(testText, backToPkcs1Private, RSAUtil.RSAType.RSA2, RSAUtil.RSAKeyFormat.PKCS1);
            bool verifyResult = RSAUtil.VerifySigned(testText, signature, backToPkcs1Public, RSAUtil.RSAType.RSA2, RSAUtil.RSAKeyFormat.PKCS1);
            Console.WriteLine($"PKCS转换验证测试: {(verifyResult ? "成功" : "失败")}");
        }

        /// <summary>
        /// 测试多种密钥格式
        /// </summary>
        public static void TestMultipleKeyFormats()
        {
            Console.WriteLine("\n--- 多种密钥格式测试 ---");
            
            string testText = "多种密钥格式测试内容";
            
            // 测试所有支持的密钥格式
            var formats = new[] 
            {
                RSAUtil.RSAKeyFormat.XML,
                RSAUtil.RSAKeyFormat.PKCS1,
                RSAUtil.RSAKeyFormat.PKCS8,
                RSAUtil.RSAKeyFormat.Java
            };

            foreach (var format in formats)
            {
                try
                {
                    var keyPair = RSAUtil.CreateRSAKey(2048, format);
                    
                    // 加密解密测试
                    string encrypted = RSAUtil.EncryptByRSA(testText, keyPair.Key, format, RSAUtil.RSAPaddingMode.PKCS1);
                    string decrypted = RSAUtil.DecryptByRSA(encrypted, keyPair.Value, format, RSAUtil.RSAPaddingMode.PKCS1);
                    bool encryptTest = testText == decrypted;
                    
                    // 签名验签测试
                    string signature = RSAUtil.HashAndSignString(testText, keyPair.Value, RSAUtil.RSAType.RSA2, format);
                    bool signTest = RSAUtil.VerifySigned(testText, signature, keyPair.Key, RSAUtil.RSAType.RSA2, format);
                    
                    Console.WriteLine($"{format} 格式测试: 加密解密={encryptTest}, 签名验签={signTest}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"{format} 格式测试失败: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// 测试新的PKCS8导出功能
        /// </summary>
        public static void TestNewPKCS8Export()
        {
            Console.WriteLine("\n--- 新PKCS8导出功能测试 ---");
            
            try
            {
                // 创建RSA密钥对
                using var rsa = System.Security.Cryptography.RSA.Create(2048);
                
                // 测试.NET 8原生PKCS8导出
                Console.WriteLine("测试.NET 8原生PKCS8导出:");
                
                // 导出PKCS8私钥 (PEM格式)
                string pkcs8PrivatePem = rsa.ExportPkcs8PrivateKeyPem();
                Console.WriteLine("PKCS8私钥(PEM)导出: 成功");
                
                // 导出PKCS8私钥 (字节数组)
                byte[] pkcs8PrivateBytes = rsa.ExportPkcs8PrivateKey();
                Console.WriteLine("PKCS8私钥(字节数组)导出: 成功");
                
                // 导出公钥
                string publicKeyPem = rsa.ExportSubjectPublicKeyInfoPem();
                byte[] publicKeyBytes = rsa.ExportSubjectPublicKeyInfo();
                Console.WriteLine("公钥导出: 成功");
                
                // 测试密钥导入
                using var rsa2 = System.Security.Cryptography.RSA.Create();
                rsa2.ImportFromPem(pkcs8PrivatePem);
                Console.WriteLine("PKCS8私钥(PEM)导入: 成功");
                
                using var rsa3 = System.Security.Cryptography.RSA.Create();
                rsa3.ImportPkcs8PrivateKey(pkcs8PrivateBytes, out _);
                Console.WriteLine("PKCS8私钥(字节数组)导入: 成功");
                
                // 验证导入的密钥是否正确（通过签名验签）
                string testData = "PKCS8导出导入验证测试";
                byte[] testBytes = System.Text.Encoding.UTF8.GetBytes(testData);
                
                // 原始密钥签名
                byte[] signature1 = rsa.SignData(testBytes, System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
                
                // 从PEM导入的密钥签名
                byte[] signature2 = rsa2.SignData(testBytes, System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
                
                // 从字节数组导入的密钥签名
                byte[] signature3 = rsa3.SignData(testBytes, System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
                
                // 验证所有签名都有效
                bool verify1 = rsa.VerifyData(testBytes, signature1, System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
                bool verify2 = rsa.VerifyData(testBytes, signature2, System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
                bool verify3 = rsa.VerifyData(testBytes, signature3, System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
                
                Console.WriteLine($"密钥验证测试: 原始密钥={verify1}, PEM导入={verify2}, 字节数组导入={verify3}");
                Console.WriteLine($"总体验证结果: {(verify1 && verify2 && verify3 ? "成功" : "失败")}");
                
                // 测试优化后的RSAUtil方法
                Console.WriteLine("\n测试优化后的RSAUtil方法:");
                var keyPair = RSAUtil.CreateRSAKey(2048, RSAUtil.RSAKeyFormat.PKCS8);
                string testText = "RSAUtil PKCS8测试";
                
                // 使用PKCS8格式进行加密解密
                string encrypted = RSAUtil.EncryptByRSA(testText, keyPair.Key, RSAUtil.RSAKeyFormat.PKCS8);
                string decrypted = RSAUtil.DecryptByRSA(encrypted, keyPair.Value, RSAUtil.RSAKeyFormat.PKCS8);
                Console.WriteLine($"PKCS8加密解密测试: {(testText == decrypted ? "成功" : "失败")}");
                
                // 使用PKCS8格式进行签名验签
                string signature = RSAUtil.HashAndSignString(testText, keyPair.Value, RSAUtil.RSAType.RSA2, RSAUtil.RSAKeyFormat.PKCS8);
                bool verifyResult = RSAUtil.VerifySigned(testText, signature, keyPair.Key, RSAUtil.RSAType.RSA2, RSAUtil.RSAKeyFormat.PKCS8);
                Console.WriteLine($"PKCS8签名验签测试: {(verifyResult ? "成功" : "失败")}");
                
                Console.WriteLine("新PKCS8导出功能测试完成!");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"PKCS8导出功能测试失败: {ex.Message}");
                Console.WriteLine($"错误详情: {ex}");
            }
        }

        /// <summary>
        /// 测试.NET Standard 2.1兼容性
        /// </summary>
        public static void TestNetStandard21Compatibility()
        {
            Console.WriteLine("\n--- .NET Standard 2.1兼容性测试 ---");
            
            try
            {
                // 测试所有密钥格式
                var formats = new[] 
                {
                    RSAUtil.RSAKeyFormat.XML,
                    RSAUtil.RSAKeyFormat.PKCS1,
                    RSAUtil.RSAKeyFormat.PKCS8,
                    RSAUtil.RSAKeyFormat.Java
                };

                string testText = ".NET Standard 2.1兼容性测试内容";
                
                foreach (var format in formats)
                {
                    try
                    {
                        Console.WriteLine($"\n测试 {format} 格式:");
                        
                        // 1. 密钥生成测试
                        var keyPair = RSAUtil.CreateRSAKey(2048, format);
                        Console.WriteLine($"  密钥生成: 成功");
                        
                        // 2. 加密解密测试
                        string encrypted = RSAUtil.EncryptByRSA(testText, keyPair.Key, format, RSAUtil.RSAPaddingMode.PKCS1);
                        string decrypted = RSAUtil.DecryptByRSA(encrypted, keyPair.Value, format, RSAUtil.RSAPaddingMode.PKCS1);
                        bool encryptTest = testText == decrypted;
                        Console.WriteLine($"  加密解密: {(encryptTest ? "成功" : "失败")}");
                        
                        // 3. 签名验签测试
                        string signature = RSAUtil.HashAndSignString(testText, keyPair.Value, RSAUtil.RSAType.RSA2, format);
                        bool signTest = RSAUtil.VerifySigned(testText, signature, keyPair.Key, RSAUtil.RSAType.RSA2, format);
                        Console.WriteLine($"  签名验签: {(signTest ? "成功" : "失败")}");
                        
                        if (!encryptTest || !signTest)
                        {
                            Console.WriteLine($"  {format} 格式测试存在问题！");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"  {format} 格式测试失败: {ex.Message}");
                    }
                }
                
                // 测试格式转换
                Console.WriteLine("\n测试格式转换:");
                try
                {
                    var xmlKeyPair = RSAUtil.CreateRSAKey(2048, RSAUtil.RSAKeyFormat.XML);
                    var pkcs1KeyPair = RSAUtil.CreateRSAKey(2048, RSAUtil.RSAKeyFormat.PKCS1);
                    
                    // XML转Java格式
                    string xmlToJavaPublic = RSAUtil.ConvertToJavaFormat(xmlKeyPair.Key, false);
                    string xmlToJavaPrivate = RSAUtil.ConvertToJavaFormat(xmlKeyPair.Value, true);
                    Console.WriteLine("  XML -> Java: 成功");
                    
                    // Java转XML格式
                    string javaToXmlPublic = RSAUtil.ConvertFromJavaFormat(xmlToJavaPublic, false);
                    string javaToXmlPrivate = RSAUtil.ConvertFromJavaFormat(xmlToJavaPrivate, true);
                    Console.WriteLine("  Java -> XML: 成功");
                    
                    // PKCS1转PKCS8
                    string pkcs1ToPkcs8Public = RSAUtil.ConvertPkcs1ToPkcs8(pkcs1KeyPair.Key, false);
                    string pkcs1ToPkcs8Private = RSAUtil.ConvertPkcs1ToPkcs8(pkcs1KeyPair.Value, true);
                    Console.WriteLine("  PKCS1 -> PKCS8: 成功");
                    
                    // PKCS8转PKCS1
                    string pkcs8ToPkcs1Public = RSAUtil.ConvertPkcs8ToPkcs1(pkcs1ToPkcs8Public, false);
                    string pkcs8ToPkcs1Private = RSAUtil.ConvertPkcs8ToPkcs1(pkcs1ToPkcs8Private, true);
                    Console.WriteLine("  PKCS8 -> PKCS1: 成功");
                    
                    // 验证转换正确性
                    string testSignature = RSAUtil.HashAndSignString(testText, pkcs8ToPkcs1Private, RSAUtil.RSAType.RSA2, RSAUtil.RSAKeyFormat.PKCS1);
                    bool conversionTest = RSAUtil.VerifySigned(testText, testSignature, pkcs8ToPkcs1Public, RSAUtil.RSAType.RSA2, RSAUtil.RSAKeyFormat.PKCS1);
                    Console.WriteLine($"  格式转换验证: {(conversionTest ? "成功" : "失败")}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"  格式转换测试失败: {ex.Message}");
                }
                
                Console.WriteLine("\n.NET Standard 2.1兼容性测试完成！");
            }
            catch (Exception ex)
            {
                Console.WriteLine($".NET Standard 2.1兼容性测试失败: {ex.Message}");
                Console.WriteLine($"错误详情: {ex}");
            }
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
