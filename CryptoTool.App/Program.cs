using CryptoTool.Common;
using CryptoTool.Common.GM;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoTool.App
{
    class Program
    {
        static void Main(string[] args)
        {
            //MedicareTest();
            //AliyunCSBTest();
            //MD5Test();
            //RSATest();
            //AESTest();
            //DESTest();

            //SM2Test();
            //SM3Test();
            //SM4Test();
        }

        public static void MedicareTest()
        {
            Console.WriteLine("\n--------------医保MedicareUtil测试---------------");

            string appId = "43AF047BBA47FC8A1AE8EFB2XXXXXXXX";
            string appSecret = "4117E877F5FA0A0188891283E4B617D5";
            long timeStamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            // 生成一对SM2密钥用于签名/验签
            var keyPair = SM2Util.GenerateKeyPair();
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

        #region DES测试

        public static void DESTest()
        {
            Console.WriteLine("--------------DES算法全面测试---------------");

            // 1. 基础字符串加密测试
            TestBasicDESFunctionality();

            // 2. 多种加密模式测试
            TestDESModes();

            // 3. 填充模式测试
            TestDESPaddingModes();

            // 4. 输出格式测试
            TestDESOutputFormats();

            // 5. 文件加密测试
            TestDESFileEncryption();

            // 6. 流式加密测试
            TestDESStreamEncryption();

            // 7. 密钥生成测试
            TestDESKeyGeneration();

            // 8. 验证功能测试
            TestDESVerification();

            // 9. 异步操作测试
            TestDESAsyncOperations();

            // 10. 性能和边界测试
            TestDESPerformanceAndBoundaries();

            Console.WriteLine("\nDES算法全面测试完成！");
        }

        /// <summary>
        /// 测试基础DES功能
        /// </summary>
        public static void TestBasicDESFunctionality()
        {
            Console.WriteLine("\n--- 基础DES功能测试 ---");

            try
            {
                string[] testInputs = {
                    "Hello World",
                    "DES加密算法测试",
                    "这是包含中文和English mixed content的测试!",
                    "123456789",
                    "The quick brown fox jumps over the lazy dog"
                };

                string key = "justdoit"; // 8字节密钥

                foreach (string input in testInputs)
                {
                    try
                    {
                        // 使用默认参数加密解密
                        string encrypted = DESUtil.EncryptByDES(input, key);
                        string decrypted = DESUtil.DecryptByDES(encrypted, key);

                        bool success = input == decrypted;
                        Console.WriteLine($"输入: \"{(input.Length > 30 ? input.Substring(0, 30) + "..." : input)}\"");
                        Console.WriteLine($"  加密结果: {encrypted.Substring(0, Math.Min(40, encrypted.Length))}...");
                        Console.WriteLine($"  解密结果: {decrypted}");
                        Console.WriteLine($"  测试结果: {(success ? "成功" : "失败")}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"输入 \"{input}\" 测试失败: {ex.Message}");
                    }
                }

                // 测试空字符串
                try
                {
                    DESUtil.EncryptByDES("", key);
                    Console.WriteLine("空字符串测试: 失败 (应该抛出异常)");
                }
                catch (ArgumentException)
                {
                    Console.WriteLine("空字符串测试: 成功 (正确抛出ArgumentException)");
                }

                // 测试null输入
                try
                {
                    DESUtil.EncryptByDES(null, key);
                    Console.WriteLine("null输入测试: 失败 (应该抛出异常)");
                }
                catch (ArgumentException)
                {
                    Console.WriteLine("null输入测试: 成功 (正确抛出ArgumentException)");
                }

                // 测试无效密钥
                try
                {
                    DESUtil.EncryptByDES("test", "短密钥");
                    Console.WriteLine("短密钥测试: 失败 (应该抛出异常)");
                }
                catch (ArgumentException)
                {
                    Console.WriteLine("短密钥测试: 成功 (正确抛出ArgumentException)");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"基础DES功能测试失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 测试不同的DES加密模式
        /// </summary>
        public static void TestDESModes()
        {
            Console.WriteLine("\n--- DES加密模式测试 ---");

            string plaintext = "DES加密模式测试内容";
            string key = "testkey1"; // 8字节密钥
            string iv = "initvect"; // 8字节初始化向量

            var modes = new[]
            {
                DESUtil.DESMode.ECB,
                DESUtil.DESMode.CBC,
                DESUtil.DESMode.CFB,
                DESUtil.DESMode.OFB
            };

            foreach (var mode in modes)
            {
                try
                {
                    string currentIv = mode == DESUtil.DESMode.ECB ? null : iv;

                    string encrypted = DESUtil.EncryptByDES(plaintext, key, mode, DESUtil.DESPadding.PKCS7, DESUtil.OutputFormat.Base64, currentIv);
                    string decrypted = DESUtil.DecryptByDES(encrypted, key, mode, DESUtil.DESPadding.PKCS7, DESUtil.OutputFormat.Base64, currentIv);

                    bool success = plaintext == decrypted;
                    Console.WriteLine($"{mode} 模式测试: {(success ? "成功" : "失败")}");
                    Console.WriteLine($"  密文长度: {encrypted.Length}");
                    Console.WriteLine($"  密文示例: {encrypted.Substring(0, Math.Min(50, encrypted.Length))}...");

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
        /// 测试不同的填充模式
        /// </summary>
        public static void TestDESPaddingModes()
        {
            Console.WriteLine("\n--- DES填充模式测试 ---");

            string plaintext = "DES填充模式测试内容"; // 确保不是8字节的倍数
            string key = "testkey1"; // 8字节密钥
            string iv = "initvect"; // 8字节初始化向量

            var paddingModes = new[]
            {
                DESUtil.DESPadding.PKCS7,
                DESUtil.DESPadding.Zeros,
                DESUtil.DESPadding.None
            };

            foreach (var padding in paddingModes)
            {
                try
                {
                    // None填充需要确保数据长度是8的倍数
                    string testText = padding == DESUtil.DESPadding.None
                        ? "12345678" // 8字节对齐
                        : plaintext;

                    string encrypted = DESUtil.EncryptByDES(testText, key, DESUtil.DESMode.CBC, padding, DESUtil.OutputFormat.Base64, iv);
                    string decrypted = DESUtil.DecryptByDES(encrypted, key, DESUtil.DESMode.CBC, padding, DESUtil.OutputFormat.Base64, iv);

                    bool success = false;
                    switch (padding)
                    {
                        case DESUtil.DESPadding.PKCS7:
                            success = testText == decrypted;
                            break;
                        case DESUtil.DESPadding.Zeros:
                            success = decrypted.TrimEnd('\0') == testText;
                            break;
                        case DESUtil.DESPadding.None:
                            success = testText == decrypted;
                            break;
                    }

                    Console.WriteLine($"{padding} 填充测试: {(success ? "成功" : "失败")}");
                    if (padding == DESUtil.DESPadding.Zeros && !success)
                    {
                        Console.WriteLine($"  原文: \"{testText}\"");
                        Console.WriteLine($"  解密: \"{decrypted}\"");
                        Console.WriteLine($"  去零: \"{decrypted.TrimEnd('\0')}\"");
                    }
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
        public static void TestDESOutputFormats()
        {
            Console.WriteLine("\n--- DES输出格式测试 ---");

            string plaintext = "DES输出格式测试内容";
            string key = "testkey1"; // 8字节密钥
            string iv = "initvect"; // 8字节初始化向量

            var formats = new[]
            {
                DESUtil.OutputFormat.Base64,
                DESUtil.OutputFormat.Hex
            };

            foreach (var format in formats)
            {
                try
                {
                    string encrypted = DESUtil.EncryptByDES(plaintext, key, DESUtil.DESMode.CBC, DESUtil.DESPadding.PKCS7, format, iv);
                    string decrypted = DESUtil.DecryptByDES(encrypted, key, DESUtil.DESMode.CBC, DESUtil.DESPadding.PKCS7, format, iv);

                    bool success = plaintext == decrypted;
                    Console.WriteLine($"{format} 格式测试: {(success ? "成功" : "失败")}");
                    Console.WriteLine($"  密文长度: {encrypted.Length}");
                    Console.WriteLine($"  密文示例: {encrypted.Substring(0, Math.Min(60, encrypted.Length))}...");

                    // 验证格式正确性
                    if (format == DESUtil.OutputFormat.Base64)
                    {
                        try
                        {
                            Convert.FromBase64String(encrypted);
                            Console.WriteLine($"  Base64格式验证: 成功");
                        }
                        catch
                        {
                            Console.WriteLine($"  Base64格式验证: 失败");
                        }
                    }
                    else if (format == DESUtil.OutputFormat.Hex)
                    {
                        bool isValidHex = encrypted.All(c => "0123456789ABCDEFabcdef".Contains(c));
                        Console.WriteLine($"  16进制格式验证: {(isValidHex ? "成功" : "失败")}");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"{format} 格式测试失败: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// 测试DES文件加密
        /// </summary>
        public static void TestDESFileEncryption()
        {
            Console.WriteLine("\n--- DES文件加密测试 ---");

            try
            {
                string testContent = "这是用于测试DES文件加密的内容。\n包含多行文本和特殊字符：!@#$%^&*()";
                string tempDir = Path.GetTempPath();
                string originalFile = Path.Combine(tempDir, "des_test_original.txt");
                string encryptedFile = Path.Combine(tempDir, "des_test_encrypted.bin");
                string decryptedFile = Path.Combine(tempDir, "des_test_decrypted.txt");

                string key = "filekey1"; // 8字节密钥
                string iv = "fileinit"; // 8字节初始化向量

                try
                {
                    // 创建测试文件
                    File.WriteAllText(originalFile, testContent, Encoding.UTF8);
                    Console.WriteLine($"创建测试文件: {Path.GetFileName(originalFile)} ({new FileInfo(originalFile).Length} 字节)");

                    // 加密文件
                    var startTime = DateTime.Now;
                    DESUtil.EncryptFile(originalFile, encryptedFile, key, DESUtil.DESMode.CBC, DESUtil.DESPadding.PKCS7, iv);
                    var encryptTime = DateTime.Now - startTime;
                    Console.WriteLine($"文件加密完成，耗时: {encryptTime.TotalMilliseconds:F2} ms");
                    Console.WriteLine($"加密文件大小: {new FileInfo(encryptedFile).Length} 字节");

                    // 解密文件
                    startTime = DateTime.Now;
                    DESUtil.DecryptFile(encryptedFile, decryptedFile, key, DESUtil.DESMode.CBC, DESUtil.DESPadding.PKCS7, iv);
                    var decryptTime = DateTime.Now - startTime;
                    Console.WriteLine($"文件解密完成，耗时: {decryptTime.TotalMilliseconds:F2} ms");

                    // 验证内容
                    string decryptedContent = File.ReadAllText(decryptedFile, Encoding.UTF8);
                    bool success = testContent == decryptedContent;
                    Console.WriteLine($"文件内容验证: {(success ? "成功" : "失败")}");

                    if (!success)
                    {
                        Console.WriteLine($"原始内容长度: {testContent.Length}");
                        Console.WriteLine($"解密内容长度: {decryptedContent.Length}");
                    }
                }
                finally
                {
                    // 清理临时文件
                    try
                    {
                        if (File.Exists(originalFile)) File.Delete(originalFile);
                        if (File.Exists(encryptedFile)) File.Delete(encryptedFile);
                        if (File.Exists(decryptedFile)) File.Delete(decryptedFile);
                    }
                    catch { }
                }

                // 测试大文件加密
                Console.WriteLine("\n大文件加密测试:");
                string largeFile = Path.Combine(tempDir, "des_large_test.txt");
                string largeEncrypted = Path.Combine(tempDir, "des_large_encrypted.bin");
                string largeDecrypted = Path.Combine(tempDir, "des_large_decrypted.txt");

                try
                {
                    // 创建1MB的测试文件
                    string largeContent = new string('A', 1024 * 1024);
                    File.WriteAllText(largeFile, largeContent);
                    Console.WriteLine($"创建大文件: {new FileInfo(largeFile).Length:N0} 字节");

                    var largeStartTime = DateTime.Now;
                    DESUtil.EncryptFile(largeFile, largeEncrypted, key, DESUtil.DESMode.CBC, DESUtil.DESPadding.PKCS7, iv);
                    var largeEncryptTime = DateTime.Now - largeStartTime;

                    largeStartTime = DateTime.Now;
                    DESUtil.DecryptFile(largeEncrypted, largeDecrypted, key, DESUtil.DESMode.CBC, DESUtil.DESPadding.PKCS7, iv);
                    var largeDecryptTime = DateTime.Now - largeStartTime;

                    string largeDecryptedContent = File.ReadAllText(largeDecrypted);
                    bool largeSuccess = largeContent == largeDecryptedContent;

                    Console.WriteLine($"大文件加密时间: {largeEncryptTime.TotalMilliseconds:F2} ms");
                    Console.WriteLine($"大文件解密时间: {largeDecryptTime.TotalMilliseconds:F2} ms");
                    Console.WriteLine($"大文件验证: {(largeSuccess ? "成功" : "失败")}");
                }
                finally
                {
                    try
                    {
                        if (File.Exists(largeFile)) File.Delete(largeFile);
                        if (File.Exists(largeEncrypted)) File.Delete(largeEncrypted);
                        if (File.Exists(largeDecrypted)) File.Delete(largeDecrypted);
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"文件加密测试失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 测试DES流式加密
        /// </summary>
        public static void TestDESStreamEncryption()
        {
            Console.WriteLine("\n--- DES流式加密测试 ---");

            try
            {
                string testContent = "这是用于测试DES流式加密的内容，内容较长以测试流式处理的效果。" +
                                   "Lorem ipsum dolor sit amet, consectetur adipiscing elit. " +
                                   "Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.";

                string key = "streamk1"; // 8字节密钥
                string iv = "streamiv"; // 8字节初始化向量
                byte[] keyBytes = Encoding.UTF8.GetBytes(key);
                byte[] ivBytes = Encoding.UTF8.GetBytes(iv);

                // 测试不同大小的数据流
                string[] testData = {
                    "小数据流",
                    testContent,
                    new string('X', 10000) // 10KB数据
                };

                foreach (string data in testData)
                {
                    try
                    {
                        using (var inputStream = new MemoryStream(Encoding.UTF8.GetBytes(data)))
                        using (var encryptedStream = new MemoryStream())
                        using (var decryptedStream = new MemoryStream())
                        {
                            var startTime = DateTime.Now;

                            // 加密
                            DESUtil.EncryptStream(inputStream, encryptedStream, keyBytes, DESUtil.DESMode.CBC, DESUtil.DESPadding.PKCS7, ivBytes);
                            var encryptTime = DateTime.Now - startTime;

                            Console.WriteLine($"数据大小: {data.Length:N0} 字节");
                            Console.WriteLine($"  加密时间: {encryptTime.TotalMilliseconds:F2} ms");
                            Console.WriteLine($"  加密后大小: {encryptedStream.Length:N0} 字节");

                            // 解密
                            encryptedStream.Position = 0;
                            startTime = DateTime.Now;
                            DESUtil.DecryptStream(encryptedStream, decryptedStream, keyBytes, DESUtil.DESMode.CBC, DESUtil.DESPadding.PKCS7, ivBytes);
                            var decryptTime = DateTime.Now - startTime;

                            Console.WriteLine($"  解密时间: {decryptTime.TotalMilliseconds:F2} ms");

                            // 验证
                            string decryptedContent = Encoding.UTF8.GetString(decryptedStream.ToArray());
                            bool success = data == decryptedContent;
                            Console.WriteLine($"  验证结果: {(success ? "成功" : "失败")}");

                            if (!success)
                            {
                                Console.WriteLine($"  原始长度: {data.Length}");
                                Console.WriteLine($"  解密长度: {decryptedContent.Length}");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"流加密测试失败 (数据长度: {data.Length}): {ex.Message}");
                    }
                }

                // 测试null流异常处理
                try
                {
                    DESUtil.EncryptStream(null, new MemoryStream(), keyBytes);
                    Console.WriteLine("null输入流测试: 失败 (应该抛出异常)");
                }
                catch (ArgumentNullException)
                {
                    Console.WriteLine("null输入流测试: 成功 (正确抛出ArgumentNullException)");
                }

                try
                {
                    DESUtil.EncryptStream(new MemoryStream(), null, keyBytes);
                    Console.WriteLine("null输出流测试: 失败 (应该抛出异常)");
                }
                catch (ArgumentNullException)
                {
                    Console.WriteLine("null输出流测试: 成功 (正确抛出ArgumentNullException)");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"流式加密测试失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 测试DES密钥生成
        /// </summary>
        public static void TestDESKeyGeneration()
        {
            Console.WriteLine("\n--- DES密钥生成测试 ---");

            try
            {
                // 测试密钥生成
                string key1 = DESUtil.GenerateKey(DESUtil.OutputFormat.Base64);
                string key2 = DESUtil.GenerateKey(DESUtil.OutputFormat.Base64);
                string hexKey = DESUtil.GenerateKey(DESUtil.OutputFormat.Hex);

                Console.WriteLine($"Base64密钥1: {key1}");
                Console.WriteLine($"Base64密钥2: {key2}");
                Console.WriteLine($"16进制密钥: {hexKey}");

                // 验证密钥格式
                try
                {
                    byte[] key1Bytes = Convert.FromBase64String(key1);
                    bool validLength1 = key1Bytes.Length == 8;
                    Console.WriteLine($"Base64密钥1长度验证: {(validLength1 ? "成功" : "失败")} ({key1Bytes.Length} 字节)");
                }
                catch
                {
                    Console.WriteLine("Base64密钥1格式验证: 失败");
                }

                bool isValidHex = hexKey.All(c => "0123456789ABCDEFabcdef".Contains(c));
                bool validHexLength = hexKey.Length == 16; // 8字节 = 16个16进制字符
                Console.WriteLine($"16进制密钥格式验证: {(isValidHex ? "成功" : "失败")}");
                Console.WriteLine($"16进制密钥长度验证: {(validHexLength ? "成功" : "失败")} ({hexKey.Length} 字符)");

                // 验证密钥随机性
                bool randomness = key1 != key2;
                Console.WriteLine($"密钥随机性验证: {(randomness ? "成功" : "失败")}");

                // 测试IV生成
                string iv1 = DESUtil.GenerateIV(DESUtil.OutputFormat.Base64);
                string iv2 = DESUtil.GenerateIV(DESUtil.OutputFormat.Base64);
                string hexIV = DESUtil.GenerateIV(DESUtil.OutputFormat.Hex);

                Console.WriteLine($"Base64 IV1: {iv1}");
                Console.WriteLine($"Base64 IV2: {iv2}");
                Console.WriteLine($"16进制 IV: {hexIV}");

                // 验证IV格式
                try
                {
                    byte[] iv1Bytes = Convert.FromBase64String(iv1);
                    bool validIVLength = iv1Bytes.Length == 8;
                    Console.WriteLine($"IV长度验证: {(validIVLength ? "成功" : "失败")} ({iv1Bytes.Length} 字节)");
                }
                catch
                {
                    Console.WriteLine("IV格式验证: 失败");
                }

                bool ivRandomness = iv1 != iv2;
                Console.WriteLine($"IV随机性验证: {(ivRandomness ? "成功" : "失败")}");

                // 使用生成的密钥进行加密测试
                string testText = "使用生成密钥的测试";
                try
                {
                    // 1. 将Base64格式的密钥和IV解码为字节数组
                    byte[] keyBytes = Convert.FromBase64String(key1);
                    byte[] ivBytes = Convert.FromBase64String(iv1);

                    // 2. 将待加密的文本转换为字节数组
                    byte[] textBytes = Encoding.UTF8.GetBytes(testText);

                    // 3. 使用接受字节数组的重载方法进行加密
                    byte[] encryptedBytes = DESUtil.EncryptByDES(textBytes, keyBytes, ivBytes: ivBytes);

                    // 4. 解密
                    byte[] decryptedBytes = DESUtil.DecryptByDES(encryptedBytes, keyBytes, ivBytes: ivBytes);

                    // 5. 将解密后的字节数组转换回字符串并验证
                    string decryptedText = Encoding.UTF8.GetString(decryptedBytes);
                    bool keyTest = testText == decryptedText;
                    Console.WriteLine($"生成密钥功能验证: {(keyTest ? "成功" : "失败")}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"生成密钥功能验证: 失败 ({ex.Message})");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"密钥生成测试失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 测试DES验证功能
        /// </summary>
        public static void TestDESVerification()
        {
            Console.WriteLine("\n--- DES验证功能测试 ---");

            try
            {
                string originalText = "DES验证功能测试内容";
                string key = "verifyky"; // 8字节密钥
                string iv = "verifyiv"; // 8字节IV

                // 测试正确验证
                string encrypted = DESUtil.EncryptByDES(originalText, key, DESUtil.DESMode.CBC, DESUtil.DESPadding.PKCS7, DESUtil.OutputFormat.Base64, iv);
                bool correctVerify = DESUtil.VerifyDES(originalText, encrypted, key, DESUtil.DESMode.CBC, DESUtil.DESPadding.PKCS7, DESUtil.OutputFormat.Base64, iv);
                Console.WriteLine($"正确验证测试: {(correctVerify ? "成功" : "失败")}");

                // 测试错误的原文验证
                bool wrongOriginal = DESUtil.VerifyDES("错误的原文", encrypted, key, DESUtil.DESMode.CBC, DESUtil.DESPadding.PKCS7, DESUtil.OutputFormat.Base64, iv);
                Console.WriteLine($"错误原文验证: {(!wrongOriginal ? "成功" : "失败")}");

                // 测试错误的密钥验证
                bool wrongKey = DESUtil.VerifyDES(originalText, encrypted, "wrongkey", DESUtil.DESMode.CBC, DESUtil.DESPadding.PKCS7, DESUtil.OutputFormat.Base64, iv);
                Console.WriteLine($"错误密钥验证: {(!wrongKey ? "成功" : "失败")}");

                // 测试错误的密文验证
                bool wrongCipher = DESUtil.VerifyDES(originalText, "错误的密文", key, DESUtil.DESMode.CBC, DESUtil.DESPadding.PKCS7, DESUtil.OutputFormat.Base64, iv);
                Console.WriteLine($"错误密文验证: {(!wrongCipher ? "成功" : "失败")}");

                // 测试不同模式的验证
                var modes = new[] { DESUtil.DESMode.ECB, DESUtil.DESMode.CBC, DESUtil.DESMode.CFB, DESUtil.DESMode.OFB };
                foreach (var mode in modes)
                {
                    try
                    {
                        string currentIv = mode == DESUtil.DESMode.ECB ? null : iv;
                        string modeEncrypted = DESUtil.EncryptByDES(originalText, key, mode, DESUtil.DESPadding.PKCS7, DESUtil.OutputFormat.Base64, currentIv);
                        bool modeVerify = DESUtil.VerifyDES(originalText, modeEncrypted, key, mode, DESUtil.DESPadding.PKCS7, DESUtil.OutputFormat.Base64, currentIv);
                        Console.WriteLine($"{mode}模式验证: {(modeVerify ? "成功" : "失败")}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"{mode}模式验证: 失败 ({ex.Message})");
                    }
                }

                // 测试不同格式的验证
                var formats = new[] { DESUtil.OutputFormat.Base64, DESUtil.OutputFormat.Hex };
                foreach (var format in formats)
                {
                    try
                    {
                        string formatEncrypted = DESUtil.EncryptByDES(originalText, key, DESUtil.DESMode.CBC, DESUtil.DESPadding.PKCS7, format, iv);
                        bool formatVerify = DESUtil.VerifyDES(originalText, formatEncrypted, key, DESUtil.DESMode.CBC, DESUtil.DESPadding.PKCS7, format, iv);
                        Console.WriteLine($"{format}格式验证: {(formatVerify ? "成功" : "失败")}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"{format}格式验证: 失败 ({ex.Message})");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"验证功能测试失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 测试DES异步操作
        /// </summary>
        public static void TestDESAsyncOperations()
        {
            Console.WriteLine("\n--- DES异步操作测试 ---");

            try
            {
                string tempDir = Path.GetTempPath();
                string[] testFiles = new string[3];
                testFiles[0] = Path.Combine(tempDir, "des_async_test1.txt");
                testFiles[1] = Path.Combine(tempDir, "des_async_test2.txt");
                testFiles[2] = Path.Combine(tempDir, "des_async_test3.txt");

                string[] encryptedFiles = new string[3];
                encryptedFiles[0] = Path.Combine(tempDir, "des_async_encrypted1.bin");
                encryptedFiles[1] = Path.Combine(tempDir, "des_async_encrypted2.bin");
                encryptedFiles[2] = Path.Combine(tempDir, "des_async_encrypted3.bin");

                string[] decryptedFiles = new string[3];
                decryptedFiles[0] = Path.Combine(tempDir, "des_async_decrypted1.txt");
                decryptedFiles[1] = Path.Combine(tempDir, "des_async_decrypted2.txt");
                decryptedFiles[2] = Path.Combine(tempDir, "des_async_decrypted3.txt");

                string key = "asynckey"; // 8字节密钥

                try
                {
                    // 创建测试文件
                    File.WriteAllText(testFiles[0], "异步测试文件1", Encoding.UTF8);
                    File.WriteAllText(testFiles[1], new string('B', 50000), Encoding.UTF8); // 50KB
                    File.WriteAllText(testFiles[2], "异步测试文件3 - 与文件1不同内容", Encoding.UTF8);

                    // 异步加密测试
                    Task.Run(async () =>
                    {
                        try
                        {
                            var startTime = DateTime.Now;

                            // 并行异步加密
                            var encryptTasks = new Task[3];
                            for (int i = 0; i < 3; i++)
                            {
                                int index = i; // 捕获循环变量
                                encryptTasks[i] = DESUtil.EncryptFileAsync(testFiles[index], encryptedFiles[index], key);
                            }

                            await Task.WhenAll(encryptTasks);
                            var encryptTime = DateTime.Now - startTime;
                            Console.WriteLine($"异步加密完成，总耗时: {encryptTime.TotalMilliseconds:F2} ms");

                            // 并行异步解密
                            startTime = DateTime.Now;
                            var decryptTasks = new Task[3];
                            for (int i = 0; i < 3; i++)
                            {
                                int index = i; // 捕获循环变量
                                decryptTasks[i] = DESUtil.DecryptFileAsync(encryptedFiles[index], decryptedFiles[index], key);
                            }

                            await Task.WhenAll(decryptTasks);
                            var decryptTime = DateTime.Now - startTime;
                            Console.WriteLine($"异步解密完成，总耗时: {decryptTime.TotalMilliseconds:F2} ms");

                            // 验证结果
                            for (int i = 0; i < 3; i++)
                            {
                                if (File.Exists(testFiles[i]) && File.Exists(decryptedFiles[i]))
                                {
                                    string original = File.ReadAllText(testFiles[i], Encoding.UTF8);
                                    string decrypted = File.ReadAllText(decryptedFiles[i], Encoding.UTF8);
                                    bool success = original == decrypted;

                                    var originalSize = new FileInfo(testFiles[i]).Length;
                                    var encryptedSize = new FileInfo(encryptedFiles[i]).Length;
                                    var decryptedSize = new FileInfo(decryptedFiles[i]).Length;

                                    Console.WriteLine($"文件{i + 1}异步处理:");
                                    Console.WriteLine($"  原始大小: {originalSize:N0} 字节");
                                    Console.WriteLine($"  加密大小: {encryptedSize:N0} 字节");
                                    Console.WriteLine($"  解密大小: {decryptedSize:N0} 字节");
                                    Console.WriteLine($"  验证结果: {(success ? "成功" : "失败")}");
                                }
                            }

                            // 测试异步异常处理
                            try
                            {
                                await DESUtil.EncryptFileAsync("不存在的文件.txt", "输出.bin", key);
                                Console.WriteLine("异步异常测试: 失败 (应该抛出异常)");
                            }
                            catch (FileNotFoundException)
                            {
                                Console.WriteLine("异步异常测试: 成功 (正确抛出FileNotFoundException)");
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"异步异常测试: 失败 (抛出了错误的异常类型: {ex.GetType().Name})");
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"异步操作内部错误: {ex.Message}");
                        }
                    }).Wait(15000); // 等待最多15秒

                    Console.WriteLine("异步操作测试完成");
                }
                finally
                {
                    // 清理测试文件
                    var allFiles = testFiles.Concat(encryptedFiles).Concat(decryptedFiles);
                    foreach (string file in allFiles)
                    {
                        try
                        {
                            if (File.Exists(file)) File.Delete(file);
                        }
                        catch { }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"异步操作测试失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 测试DES性能和边界条件
        /// </summary>
        public static void TestDESPerformanceAndBoundaries()
        {
            Console.WriteLine("\n--- DES性能和边界测试 ---");

            try
            {
                string key = "perfkey1"; // 8字节密钥

                // 性能测试 - 大数据加密
                Console.WriteLine("大数据加密性能测试:");
                var dataSizes = new[] { 1024, 10240, 102400, 1048576 }; // 1KB, 10KB, 100KB, 1MB

                foreach (int size in dataSizes)
                {
                    try
                    {
                        string largeData = new string('A', size);

                        var startTime = DateTime.Now;
                        string encrypted = DESUtil.EncryptByDES(largeData, key);
                        var encryptTime = DateTime.Now - startTime;

                        startTime = DateTime.Now;
                        string decrypted = DESUtil.DecryptByDES(encrypted, key);
                        var decryptTime = DateTime.Now - startTime;

                        bool success = largeData == decrypted;

                        Console.WriteLine($"  {size:N0} 字节数据:");
                        Console.WriteLine($"    加密时间: {encryptTime.TotalMilliseconds:F2} ms");
                        Console.WriteLine($"    解密时间: {decryptTime.TotalMilliseconds:F2} ms");
                        Console.WriteLine($"    验证结果: {(success ? "成功" : "失败")}");
                        Console.WriteLine($"    性能评估: {(encryptTime.TotalSeconds < 1 ? "优秀" : "需要优化")}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"  {size:N0} 字节测试失败: {ex.Message}");
                    }
                }

                // 边界条件测试
                Console.WriteLine("\n边界条件测试:");

                // 测试最短有效输入
                try
                {
                    string shortText = "A";
                    string encrypted = DESUtil.EncryptByDES(shortText, key);
                    string decrypted = DESUtil.DecryptByDES(encrypted, key);
                    bool shortSuccess = shortText == decrypted;
                    Console.WriteLine($"单字符测试: {(shortSuccess ? "成功" : "失败")}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"单字符测试失败: {ex.Message}");
                }

                // 测试各种字符编码
                string[] specialTexts = {
                    "🌍🚀💻🎉", // Unicode表情符号
                    "测试中文字符",
                    "English Text",
                    "Mixed中英文Content混合",
                    "特殊字符!@#$%^&*()_+-=[]{}|;':\",./<>?`~",
                    "换行\r\n制表符\t测试\0控制字符"
                };

                foreach (string specialText in specialTexts)
                {
                    try
                    {
                        string encrypted = DESUtil.EncryptByDES(specialText, key);
                        string decrypted = DESUtil.DecryptByDES(encrypted, key);
                        bool success = specialText == decrypted;
                        string description = specialText.Length > 20 ? specialText.Substring(0, 20) + "..." : specialText;
                        Console.WriteLine($"特殊字符测试 \"{description}\": {(success ? "成功" : "失败")}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"特殊字符测试失败: {ex.Message}");
                    }
                }

                // 密钥边界测试
                Console.WriteLine("\n密钥边界测试:");

                // 测试精确8字节密钥
                string[] testKeys = {
                    "12345678", // 精确8字节
                    "测试密钥1", // 中文字符可能超过8字节
                    "test1234" // 英文8字节
                };

                foreach (string testKey in testKeys)
                {
                    try
                    {
                        byte[] keyBytes = Encoding.UTF8.GetBytes(testKey);
                        if (keyBytes.Length == 8)
                        {
                            string encrypted = DESUtil.EncryptByDES("测试内容", testKey);
                            string decrypted = DESUtil.DecryptByDES(encrypted, testKey);
                            bool success = "测试内容" == decrypted;
                            Console.WriteLine($"密钥 \"{testKey}\" ({keyBytes.Length}字节): {(success ? "成功" : "失败")}");
                        }
                        else
                        {
                            Console.WriteLine($"密钥 \"{testKey}\" ({keyBytes.Length}字节): 长度不符合要求");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"密钥 \"{testKey}\" 测试失败: {ex.Message}");
                    }
                }

                // 内存使用测试
                Console.WriteLine("\n内存使用测试:");
                try
                {
                    long beforeMemory = GC.GetTotalMemory(true);

                    // 进行多次加密解密操作
                    for (int i = 0; i < 100; i++)
                    {
                        string testData = $"内存测试数据 {i} " + new string('X', 1000);
                        string encrypted = DESUtil.EncryptByDES(testData, key);
                        string decrypted = DESUtil.DecryptByDES(encrypted, key);
                    }

                    long afterMemory = GC.GetTotalMemory(true);
                    long memoryUsed = afterMemory - beforeMemory;

                    Console.WriteLine($"内存使用量: {memoryUsed:N0} 字节");
                    Console.WriteLine($"内存使用评估: {(memoryUsed < 1024 * 1024 ? "正常" : "偏高")}"); // 小于1MB为正常
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"内存使用测试失败: {ex.Message}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"性能和边界测试失败: {ex.Message}");
            }
        }

        #endregion

        #region MD5测试

        /// <summary>
        /// MD5算法全面测试
        /// </summary>
        public static void MD5Test()
        {
            Console.WriteLine("--------------MD5算法全面测试---------------");

            // 1. 基础字符串加密测试
            TestBasicMD5Functionality();

            // 2. 多种编码格式测试
            TestMD5Encodings();

            // 3. 文件MD5测试
            TestFileMD5();

            // 4. 流MD5测试
            TestStreamMD5();

            // 5. MD5验证测试
            TestMD5Verification();

            // 6. 工具方法测试
            TestMD5UtilityMethods();

            // 7. API密钥生成测试
            TestAPIKeyGeneration();

            // 8. 性能和边界测试
            TestMD5PerformanceAndBoundaries();

            // 9. 异步操作测试
            TestMD5AsyncOperations();

            Console.WriteLine("\nMD5算法全面测试完成！");
        }

        /// <summary>
        /// 测试基础MD5功能
        /// </summary>
        public static void TestBasicMD5Functionality()
        {
            Console.WriteLine("\n--- 基础MD5功能测试 ---");

            try
            {
                string[] testInputs = {
                    "Hello World",
                    "MD5加密算法测试",
                    "这是包含中文和English mixed content的测试!",
                    "",
                    "123456789",
                    "The quick brown fox jumps over the lazy dog"
                };

                foreach (string input in testInputs)
                {
                    try
                    {
                        // 测试小写MD5
                        string lowerHash = MD5Util.EncryptByMD5(input);

                        // 测试大写MD5
                        string upperHash = MD5Util.EncryptByMD5Upper(input);

                        // 测试Base64格式
                        string base64Hash = MD5Util.EncryptByMD5ToBase64(input);

                        // 验证格式正确性
                        bool isValidLower = lowerHash.Length == 32 && lowerHash.All(c => "0123456789abcdef".Contains(c));
                        bool isValidUpper = upperHash.Length == 32 && upperHash.All(c => "0123456789ABCDEF".Contains(c));
                        bool isValidBase64 = !string.IsNullOrEmpty(base64Hash);

                        Console.WriteLine($"输入: \"{(input.Length > 20 ? input.Substring(0, 20) + "..." : input)}\"");
                        Console.WriteLine($"  小写MD5: {lowerHash} - {(isValidLower ? "true" : "false")}");
                        Console.WriteLine($"  大写MD5: {upperHash} - {(isValidUpper ? "true" : "false")}");
                        Console.WriteLine($"  Base64:  {base64Hash} - {(isValidBase64 ? "true" : "false")}");

                        // 验证大小写转换正确性
                        bool caseConsistent = lowerHash.ToUpper() == upperHash;
                        Console.WriteLine($"  大小写一致性: {(caseConsistent ? "true" : "false")}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"输入 \"{input}\" 测试失败: {ex.Message}");
                    }
                }

                // 测试null输入
                try
                {
                    MD5Util.EncryptByMD5(null);
                    Console.WriteLine("null输入测试: false (应该抛出异常)");
                }
                catch (ArgumentNullException)
                {
                    Console.WriteLine("null输入测试: true (正确抛出ArgumentNullException)");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"null输入测试: false (抛出了错误的异常类型: {ex.GetType().Name})");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"基础MD5功能测试失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 测试多种编码格式
        /// </summary>
        public static void TestMD5Encodings()
        {
            Console.WriteLine("\n--- MD5编码格式测试 ---");

            try
            {
                string testInput = "编码测试内容";
                var encodings = new[]
                {
                    Encoding.UTF8,
                    Encoding.Unicode,
                    Encoding.ASCII,
                    Encoding.UTF32
                };

                foreach (var encoding in encodings)
                {
                    try
                    {
                        string hash = MD5Util.EncryptByMD5(testInput, encoding);
                        byte[] hashBytes = MD5Util.ComputeMD5Hash(testInput, encoding);

                        Console.WriteLine($"{encoding.EncodingName}:");
                        Console.WriteLine($"  哈希值: {hash}");
                        Console.WriteLine($"  字节长度: {hashBytes.Length}");
                        Console.WriteLine($"  格式正确: {(hash.Length == 32 ? "true" : "false")}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"{encoding.EncodingName} 编码测试失败: {ex.Message}");
                    }
                }

                // 验证同一编码多次计算结果一致
                string consistencyInput = "一致性测试";
                string hash1 = MD5Util.EncryptByMD5(consistencyInput);
                string hash2 = MD5Util.EncryptByMD5(consistencyInput);
                Console.WriteLine($"一致性测试: {(hash1 == hash2 ? "true" : "false")}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"编码格式测试失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 测试文件MD5
        /// </summary>
        public static void TestFileMD5()
        {
            Console.WriteLine("\n--- 文件MD5测试 ---");

            try
            {
                string tempDir = Path.GetTempPath();
                string[] testFiles = new string[4];

                // 创建测试文件
                testFiles[0] = Path.Combine(tempDir, "md5_test_empty.txt");
                testFiles[1] = Path.Combine(tempDir, "md5_test_small.txt");
                testFiles[2] = Path.Combine(tempDir, "md5_test_large.txt");
                testFiles[3] = Path.Combine(tempDir, "md5_test_chinese.txt");

                try
                {
                    // 空文件
                    File.WriteAllText(testFiles[0], "", Encoding.UTF8);

                    // 小文件
                    File.WriteAllText(testFiles[1], "Hello World", Encoding.UTF8);

                    // 大文件 (1MB)
                    string largeContent = new string('A', 1024 * 1024);
                    File.WriteAllText(testFiles[2], largeContent, Encoding.UTF8);

                    // 中文文件
                    File.WriteAllText(testFiles[3], "这是中文测试内容，包含特殊字符！@#$%^&*()", Encoding.UTF8);

                    foreach (string filePath in testFiles)
                    {
                        if (File.Exists(filePath))
                        {
                            try
                            {
                                var startTime = DateTime.Now;

                                // 测试文件MD5计算
                                string fileMD5 = MD5Util.GetFileHashCode(filePath, "MD5");
                                string fileMD5Upper = MD5Util.GetFileHashCode(filePath, "MD5", true);

                                var endTime = DateTime.Now;
                                var duration = endTime - startTime;

                                FileInfo info = new FileInfo(filePath);
                                Console.WriteLine($"文件: {Path.GetFileName(filePath)} ({info.Length} 字节)");
                                Console.WriteLine($"  MD5(小写): {fileMD5}");
                                Console.WriteLine($"  MD5(大写): {fileMD5Upper}");
                                Console.WriteLine($"  计算时间: {duration.TotalMilliseconds:F2} ms");
                                Console.WriteLine($"  格式正确: {(fileMD5.Length == 32 ? "true" : "false")}");
                                Console.WriteLine($"  大小写一致: {(fileMD5.ToUpper() == fileMD5Upper ? "true" : "false")}");

                                // 验证文件MD5
                                bool verifyResult = MD5Util.VerifyFileMD5(filePath, fileMD5);
                                Console.WriteLine($"  验证结果: {(verifyResult ? "true" : "false")}");
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"文件 {Path.GetFileName(filePath)} 测试失败: {ex.Message}");
                            }
                        }
                    }

                    // 测试文件比较
                    Console.WriteLine("\n文件比较测试:");

                    // 创建两个相同内容的文件
                    string file1 = Path.Combine(tempDir, "md5_compare1.txt");
                    string file2 = Path.Combine(tempDir, "md5_compare2.txt");
                    string file3 = Path.Combine(tempDir, "md5_compare3.txt");

                    File.WriteAllText(file1, "相同内容", Encoding.UTF8);
                    File.WriteAllText(file2, "相同内容", Encoding.UTF8);
                    File.WriteAllText(file3, "不同内容", Encoding.UTF8);

                    bool sameFiles = MD5Util.CompareFileMD5(file1, file2);
                    bool differentFiles = MD5Util.CompareFileMD5(file1, file3);

                    Console.WriteLine($"  相同文件比较: {(sameFiles ? "true" : "false")}");
                    Console.WriteLine($"  不同文件比较: {(!differentFiles ? "true" : "false")}");

                    // 清理比较测试文件
                    try
                    {
                        File.Delete(file1);
                        File.Delete(file2);
                        File.Delete(file3);
                    }
                    catch { }

                    // 测试不存在的文件
                    string nonExistentFile = Path.Combine(tempDir, "nonexistent.txt");
                    string nonExistentResult = MD5Util.GetFileHashCode(nonExistentFile);
                    Console.WriteLine($"  不存在文件测试: {(nonExistentResult == string.Empty ? "true" : "false")}");
                }
                finally
                {
                    // 清理测试文件
                    foreach (string file in testFiles)
                    {
                        try
                        {
                            if (File.Exists(file))
                                File.Delete(file);
                        }
                        catch { }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"文件MD5测试失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 测试流MD5
        /// </summary>
        public static void TestStreamMD5()
        {
            Console.WriteLine("\n--- 流MD5测试 ---");

            try
            {
                string[] testContents = {
                    "",
                    "小流测试",
                    "这是一个较长的流测试内容，用于验证流式MD5计算功能的正确性。",
                    new string('X', 10000) // 10KB内容
                };

                foreach (string content in testContents)
                {
                    try
                    {
                        byte[] contentBytes = Encoding.UTF8.GetBytes(content);

                        using (var stream = new MemoryStream(contentBytes))
                        {
                            var startTime = DateTime.Now;

                            // 计算流MD5
                            string streamMD5 = MD5Util.ComputeStreamMD5(stream);

                            var endTime = DateTime.Now;
                            var duration = endTime - startTime;

                            // 重置流位置，计算大写版本
                            stream.Position = 0;
                            string streamMD5Upper = MD5Util.ComputeStreamMD5(stream, true);

                            // 比较与字符串MD5是否一致
                            string stringMD5 = MD5Util.EncryptByMD5(content);

                            Console.WriteLine($"流内容长度: {contentBytes.Length} 字节");
                            Console.WriteLine($"  流MD5(小写): {streamMD5}");
                            Console.WriteLine($"  流MD5(大写): {streamMD5Upper}");
                            Console.WriteLine($"  字符串MD5: {stringMD5}");
                            Console.WriteLine($"  计算时间: {duration.TotalMilliseconds:F2} ms");
                            Console.WriteLine($"  与字符串一致: {(streamMD5 == stringMD5 ? "true" : "false")}");
                            Console.WriteLine($"  大小写一致: {(streamMD5.ToUpper() == streamMD5Upper ? "true" : "false")}");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"流测试失败 (长度: {content.Length}): {ex.Message}");
                    }
                }

                // 测试null流
                try
                {
                    MD5Util.ComputeStreamMD5(null);
                    Console.WriteLine("null流测试: false (应该抛出异常)");
                }
                catch (ArgumentNullException)
                {
                    Console.WriteLine("null流测试: true (正确抛出ArgumentNullException)");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"null流测试: false (抛出了错误的异常类型: {ex.GetType().Name})");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"流MD5测试失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 测试MD5验证
        /// </summary>
        public static void TestMD5Verification()
        {
            Console.WriteLine("\n--- MD5验证测试 ---");

            try
            {
                string testInput = "验证测试内容";
                string correctHash = MD5Util.EncryptByMD5(testInput);
                string incorrectHash = "incorrect_hash_value_123456789";
                string upperHash = correctHash.ToUpper();

                // 测试正确验证
                bool correctVerify = MD5Util.VerifyMD5(testInput, correctHash);
                Console.WriteLine($"正确哈希验证: {(correctVerify ? "true" : "false")}");

                // 测试错误验证
                bool incorrectVerify = MD5Util.VerifyMD5(testInput, incorrectHash);
                Console.WriteLine($"错误哈希验证: {(!incorrectVerify ? "true" : "false")}");

                // 测试大小写不敏感
                bool caseInsensitiveVerify = MD5Util.VerifyMD5(testInput, upperHash);
                Console.WriteLine($"大小写不敏感验证: {(caseInsensitiveVerify ? "true" : "false")}");

                // 测试空值验证
                bool nullInputVerify = MD5Util.VerifyMD5(null, correctHash);
                bool nullHashVerify = MD5Util.VerifyMD5(testInput, null);
                Console.WriteLine($"null输入验证: {(!nullInputVerify ? "true" : "false")}");
                Console.WriteLine($"null哈希验证: {(!nullHashVerify ? "true" : "false")}");

                // 创建临时文件进行文件验证测试
                string tempFile = Path.GetTempFileName();
                try
                {
                    File.WriteAllText(tempFile, testInput, Encoding.UTF8);
                    string fileHash = MD5Util.GetFileHashCode(tempFile, "MD5");

                    bool fileVerifyCorrect = MD5Util.VerifyFileMD5(tempFile, fileHash);
                    bool fileVerifyIncorrect = MD5Util.VerifyFileMD5(tempFile, incorrectHash);

                    Console.WriteLine($"文件正确验证: {(fileVerifyCorrect ? "true" : "false")}");
                    Console.WriteLine($"文件错误验证: {(!fileVerifyIncorrect ? "true" : "false")}");
                }
                finally
                {
                    try
                    {
                        if (File.Exists(tempFile))
                            File.Delete(tempFile);
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"MD5验证测试失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 测试MD5工具方法
        /// </summary>
        public static void TestMD5UtilityMethods()
        {
            Console.WriteLine("\n--- MD5工具方法测试 ---");

            try
            {
                // 测试16进制字符串转换
                string hexString = "48-65-6C-6C-6F"; // "Hello" in hex
                byte[] expectedBytes = { 0x48, 0x65, 0x6C, 0x6C, 0x6F };

                try
                {
                    byte[] convertedBytes = MD5Util.GetBytesFromHexString(hexString);
                    bool bytesMatch = convertedBytes.SequenceEqual(expectedBytes);
                    Console.WriteLine($"16进制字符串转字节: {(bytesMatch ? "true" : "false")}");

                    // 反向转换测试
                    string reconvertedHex = MD5Util.GetHexStringFromBytes(convertedBytes);
                    string reconvertedHexUpper = MD5Util.GetHexStringFromBytes(convertedBytes, true);

                    Console.WriteLine($"字节转16进制(小写): {reconvertedHex}");
                    Console.WriteLine($"字节转16进制(大写): {reconvertedHexUpper}");

                    bool hexMatch = string.Equals(hexString, reconvertedHex, StringComparison.OrdinalIgnoreCase);
                    Console.WriteLine($"往返转换正确: {(hexMatch ? "true" : "false")}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"16进制转换测试失败: {ex.Message}");
                }

                // 测试无效16进制字符串
                try
                {
                    MD5Util.GetBytesFromHexString("GG-HH-II");
                    Console.WriteLine("无效16进制测试: false (应该抛出异常)");
                }
                catch (ArgumentException)
                {
                    Console.WriteLine("无效16进制测试: true (正确抛出ArgumentException)");
                }

                // 测试null参数
                try
                {
                    MD5Util.GetBytesFromHexString(null);
                    Console.WriteLine("null字符串测试: false (应该抛出异常)");
                }
                catch (ArgumentException)
                {
                    Console.WriteLine("null字符串测试: true (正确抛出ArgumentException)");
                }

                try
                {
                    MD5Util.GetHexStringFromBytes(null);
                    Console.WriteLine("null字节数组测试: false (应该抛出异常)");
                }
                catch (ArgumentNullException)
                {
                    Console.WriteLine("null字节数组测试: true (正确抛出ArgumentNullException)");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"工具方法测试失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 测试API密钥生成
        /// </summary>
        public static void TestAPIKeyGeneration()
        {
            Console.WriteLine("\n--- API密钥生成测试 ---");

            try
            {
                // 测试AppId生成
                string appId1 = MD5Util.GenerateAppId();
                string appId2 = MD5Util.GenerateAppId();

                Console.WriteLine($"AppId生成测试:");
                Console.WriteLine($"  AppId1: {appId1.Substring(0, Math.Min(20, appId1.Length))}...");
                Console.WriteLine($"  AppId2: {appId2.Substring(0, Math.Min(20, appId2.Length))}...");
                Console.WriteLine($"  随机性: {(appId1 != appId2 ? "true" : "false")}");

                // 验证Base64格式
                try
                {
                    byte[] decodedAppId = Convert.FromBase64String(appId1);
                    Console.WriteLine($"  Base64格式: true (长度: {decodedAppId.Length} 字节)");
                }
                catch
                {
                    Console.WriteLine($"  Base64格式: false");
                }

                // 测试AppSecret生成
                string appSecret1 = MD5Util.GenerateAppSecret();
                string appSecret2 = MD5Util.GenerateAppSecret();

                Console.WriteLine($"AppSecret生成测试:");
                Console.WriteLine($"  AppSecret1: {appSecret1.Substring(0, Math.Min(20, appSecret1.Length))}...");
                Console.WriteLine($"  AppSecret2: {appSecret2.Substring(0, Math.Min(20, appSecret2.Length))}...");
                Console.WriteLine($"  随机性: {(appSecret1 != appSecret2 ? "true" : "false")}");

                // 验证Base64格式
                try
                {
                    byte[] decodedAppSecret = Convert.FromBase64String(appSecret1);
                    Console.WriteLine($"  Base64格式: true (长度: {decodedAppSecret.Length} 字节)");
                }
                catch
                {
                    Console.WriteLine($"  Base64格式: false");
                }

                // 测试16进制密钥生成
                string hexKey1 = MD5Util.GenerateHexKey();
                string hexKey2 = MD5Util.GenerateHexKey(32, true);

                Console.WriteLine($"16进制密钥生成测试:");
                Console.WriteLine($"  小写16进制: {hexKey1}");
                Console.WriteLine($"  大写16进制: {hexKey2}");
                Console.WriteLine($"  随机性: {(!hexKey1.Equals(hexKey2, StringComparison.OrdinalIgnoreCase) ? "true" : "false")}");
                Console.WriteLine($"  格式正确: {(hexKey1.All(c => "0123456789abcdef".Contains(c)) ? "true" : "false")}");

                // 测试自定义长度
                string customAppId = MD5Util.GenerateAppId(16);
                string customHexKey = MD5Util.GenerateHexKey(8);

                try
                {
                    byte[] customDecoded = Convert.FromBase64String(customAppId);
                    Console.WriteLine($"自定义长度AppId: true (期望16字节，实际{customDecoded.Length}字节)");
                }
                catch
                {
                    Console.WriteLine($"自定义长度AppId: false");
                }

                Console.WriteLine($"自定义长度16进制: {(customHexKey.Length == 16 ? "true" : "false")} (期望16字符，实际{customHexKey.Length}字符)");

                // 测试无效长度
                try
                {
                    MD5Util.GenerateAppId(0);
                    Console.WriteLine("无效长度测试: false (应该抛出异常)");
                }
                catch (ArgumentException)
                {
                    Console.WriteLine("无效长度测试: true (正确抛出ArgumentException)");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"API密钥生成测试失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 测试性能和边界条件
        /// </summary>
        public static void TestMD5PerformanceAndBoundaries()
        {
            Console.WriteLine("\n--- MD5性能和边界测试 ---");

            try
            {
                // 测试大文本性能
                string largeText = new string('A', 1_000_000); // 1MB文本
                var startTime = DateTime.Now;
                string largeTextMD5 = MD5Util.EncryptByMD5(largeText);
                var endTime = DateTime.Now;
                var duration = endTime - startTime;

                Console.WriteLine($"大文本MD5计算:");
                Console.WriteLine($"  文本大小: {largeText.Length:N0} 字符");
                Console.WriteLine($"  计算时间: {duration.TotalMilliseconds:F2} ms");
                Console.WriteLine($"  结果长度: {largeTextMD5.Length}");
                Console.WriteLine($"  性能测试: {(duration.TotalSeconds < 5 ? "true" : "false")} (< 5秒)");

                // 测试Unicode字符
                string unicodeText = "🌍🚀💻🎉测试Unicode字符";
                string unicodeMD5 = MD5Util.EncryptByMD5(unicodeText);
                Console.WriteLine($"Unicode字符测试: true");
                Console.WriteLine($"  输入: {unicodeText}");
                Console.WriteLine($"  MD5: {unicodeMD5}");

                // 测试特殊字符
                string specialChars = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~";
                string specialMD5 = MD5Util.EncryptByMD5(specialChars);
                Console.WriteLine($"特殊字符测试: true");
                Console.WriteLine($"  MD5: {specialMD5}");

                // 测试换行符和控制字符
                string controlChars = "测试\r\n\t\0控制字符";
                string controlMD5 = MD5Util.EncryptByMD5(controlChars);
                Console.WriteLine($"控制字符测试: true");
                Console.WriteLine($"  MD5: {controlMD5}");

                // 测试极长路径（文件测试）
                try
                {
                    string invalidPath = new string('a', 300) + ".txt"; // 超长路径
                    string invalidResult = MD5Util.GetFileHashCode(invalidPath);
                    Console.WriteLine($"无效路径测试: {(invalidResult == string.Empty ? "true" : "false")}");
                }
                catch
                {
                    Console.WriteLine($"无效路径测试: true (正确处理异常)");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"性能和边界测试失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 测试异步操作
        /// </summary>
        public static void TestMD5AsyncOperations()
        {
            Console.WriteLine("\n--- MD5异步操作测试 ---");

            try
            {
                // 创建测试文件
                string tempDir = Path.GetTempPath();
                string testFile1 = Path.Combine(tempDir, "async_test1.txt");
                string testFile2 = Path.Combine(tempDir, "async_test2.txt");
                string testFile3 = Path.Combine(tempDir, "async_test3.txt");

                try
                {
                    // 创建不同大小的测试文件
                    File.WriteAllText(testFile1, "小文件异步测试", Encoding.UTF8);
                    File.WriteAllText(testFile2, new string('B', 100000), Encoding.UTF8); // 100KB
                    File.WriteAllText(testFile3, "小文件异步测试", Encoding.UTF8); // 与test1相同内容

                    // 异步计算文件MD5
                    Task.Run(async () =>
                    {
                        try
                        {
                            var startTime = DateTime.Now;

                            // 并行计算多个文件的MD5
                            var task1 = MD5Util.GetFileMD5Async(testFile1);
                            var task2 = MD5Util.GetFileMD5Async(testFile2);
                            var task3 = MD5Util.GetFileMD5Async(testFile3);

                            await Task.WhenAll(task1, task2, task3);

                            var endTime = DateTime.Now;
                            var duration = endTime - startTime;

                            string hash1 = task1.Result;
                            string hash2 = task2.Result;
                            string hash3 = task3.Result;

                            Console.WriteLine($"异步文件MD5计算:");
                            Console.WriteLine($"  文件1 MD5: {hash1}");
                            Console.WriteLine($"  文件2 MD5: {hash2}");
                            Console.WriteLine($"  文件3 MD5: {hash3}");
                            Console.WriteLine($"  并行计算时间: {duration.TotalMilliseconds:F2} ms");
                            Console.WriteLine($"  文件1与3相同: {(hash1 == hash3 ? "true" : "false")}");

                            // 异步文件比较
                            bool asyncCompareResult = await MD5Util.CompareFileMD5Async(testFile1, testFile3);
                            bool asyncCompareDifferent = await MD5Util.CompareFileMD5Async(testFile1, testFile2);

                            Console.WriteLine($"异步文件比较:");
                            Console.WriteLine($"  相同文件比较: {(asyncCompareResult ? "true" : "false")}");
                            Console.WriteLine($"  不同文件比较: {(!asyncCompareDifferent ? "true" : "false")}");

                            // 测试异步流MD5
                            byte[] testData = Encoding.UTF8.GetBytes("异步流测试数据");
                            using (var stream = new MemoryStream(testData))
                            {
                                string asyncStreamMD5 = await MD5Util.ComputeStreamMD5Async(stream);
                                string syncStreamMD5 = MD5Util.EncryptByMD5("异步流测试数据");

                                Console.WriteLine($"异步流MD5:");
                                Console.WriteLine($"  异步结果: {asyncStreamMD5}");
                                Console.WriteLine($"  同步结果: {syncStreamMD5}");
                                Console.WriteLine($"  结果一致: {(asyncStreamMD5 == syncStreamMD5 ? "true" : "false")}");
                            }

                            // 测试异步异常处理
                            try
                            {
                                await MD5Util.GetFileMD5Async("不存在的文件.txt");
                                Console.WriteLine("异步异常测试: false (应该抛出异常)");
                            }
                            catch (FileNotFoundException)
                            {
                                Console.WriteLine("异步异常测试: true (正确抛出FileNotFoundException)");
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"异步异常测试: false (抛出了错误的异常类型: {ex.GetType().Name})");
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"异步操作测试失败: {ex.Message}");
                        }
                    }).Wait(10000); // 等待最多10秒

                    Console.WriteLine("异步操作测试完成");
                }
                finally
                {
                    // 清理测试文件
                    try
                    {
                        if (File.Exists(testFile1)) File.Delete(testFile1);
                        if (File.Exists(testFile2)) File.Delete(testFile2);
                        if (File.Exists(testFile3)) File.Delete(testFile3);
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"异步操作测试失败: {ex.Message}");
            }
        }

        #endregion

        #region RSA测试

        /// <summary>
        /// RSA算法全面测试
        /// </summary>
        public static void RSATest()
        {
            Console.WriteLine("--------------RSA算法全面测试---------------");

            try
            {
                // 1. 基础密钥生成测试
                TestBasicRSAFunctionality();

                // 2. 密钥格式转换测试  
                TestRSAKeyFormats();

                // 3. 加解密功能测试
                TestRSAEncryption();

                // 4. 签名验签测试
                TestRSASignature();

                // 5. 证书处理测试
                TestRSACertificate();

                Console.WriteLine("\nRSA算法全面测试完成！");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"RSA测试过程中发生异常: {ex.Message}");
            }
        }

        /// <summary>
        /// 测试RSA基础功能
        /// </summary>
        public static void TestBasicRSAFunctionality()
        {
            Console.WriteLine("\n--- RSA基础功能测试 ---");

            try
            {
                // 测试不同密钥长度生成
                var keySizes = new[] { 1024, 2048, 4096 };

                foreach (var keySize in keySizes)
                {
                    var startTime = DateTime.Now;
                    var keyPair = RSAUtil.GenerateKeyPair(keySize);
                    var duration = DateTime.Now - startTime;

                    var publicKey = (Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters)keyPair.Public;
                    var privateKey = (Org.BouncyCastle.Crypto.Parameters.RsaPrivateCrtKeyParameters)keyPair.Private;

                    Console.WriteLine($"RSA-{keySize} 密钥生成: 成功 (耗时: {duration.TotalMilliseconds:F2} ms)");
                    Console.WriteLine($"  模数位数: {publicKey.Modulus.BitLength}");

                    // 测试基础加解密
                    string testText = "RSA测试内容";
                    string encrypted = RSAUtil.Encrypt(testText, publicKey);
                    string decrypted = RSAUtil.Decrypt(encrypted, privateKey);
                    bool success = testText == decrypted;
                    Console.WriteLine($"  基础加解密: {(success ? "成功" : "失败")}");
                }

                // 测试无效密钥长度
                try
                {
                    RSAUtil.GenerateKeyPair(512);
                    Console.WriteLine("无效密钥长度测试: 失败 (应该抛出异常)");
                }
                catch (ArgumentException)
                {
                    Console.WriteLine("无效密钥长度测试: 成功");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"基础功能测试失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 测试RSA密钥格式
        /// </summary>
        public static void TestRSAKeyFormats()
        {
            Console.WriteLine("\n--- RSA密钥格式测试 ---");

            try
            {
                var keyPair = RSAUtil.GenerateKeyPair(2048);
                var publicKey = (Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters)keyPair.Public;
                var privateKey = (Org.BouncyCastle.Crypto.Parameters.RsaPrivateCrtKeyParameters)keyPair.Private;

                // 测试PEM格式
                string pemPublicKey = RSAUtil.GeneratePublicKeyString(publicKey, RSAUtil.RSAKeyFormat.PEM);
                string pemPrivateKey = RSAUtil.GeneratePrivateKeyString(privateKey, RSAUtil.RSAKeyFormat.PEM);
                Console.WriteLine("PEM格式生成: 成功");

                // 测试Base64格式
                string base64PublicKey = RSAUtil.GeneratePublicKeyString(publicKey, RSAUtil.RSAKeyFormat.Base64);
                string base64PrivateKey = RSAUtil.GeneratePrivateKeyString(privateKey, RSAUtil.RSAKeyFormat.Base64);
                Console.WriteLine("Base64格式生成: 成功");

                // 测试Hex格式
                string hexPublicKey = RSAUtil.GeneratePublicKeyString(publicKey, RSAUtil.RSAKeyFormat.Hex);
                string hexPrivateKey = RSAUtil.GeneratePrivateKeyString(privateKey, RSAUtil.RSAKeyFormat.Hex);
                Console.WriteLine("Hex格式生成: 成功");

                // 测试格式解析
                var parsedPublicKey = RSAUtil.ParsePublicKeyFromPem(pemPublicKey);
                var parsedPrivateKey = RSAUtil.ParsePrivateKeyFromPem(pemPrivateKey);

                bool publicMatch = publicKey.Modulus.Equals(parsedPublicKey.Modulus);
                bool privateMatch = privateKey.Modulus.Equals(parsedPrivateKey.Modulus);
                Console.WriteLine($"格式解析验证: {(publicMatch && privateMatch ? "成功" : "失败")}");

                // 测试PKCS1到PKCS8转换
                string pkcs8PublicKey = RSAUtil.ConvertPkcs1ToPkcs8(pemPublicKey, false);
                string pkcs8PrivateKey = RSAUtil.ConvertPkcs1ToPkcs8(pemPrivateKey, true);
                Console.WriteLine("PKCS1->PKCS8转换: 成功");

                // 测试PKCS8到PKCS1转换
                string backPkcs1Public = RSAUtil.ConvertPkcs8ToPkcs1(pkcs8PublicKey, false);
                string backPkcs1Private = RSAUtil.ConvertPkcs8ToPkcs1(pkcs8PrivateKey, true);
                Console.WriteLine("PKCS8->PKCS1转换: 成功");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"密钥格式测试失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 测试RSA加密功能
        /// </summary>
        public static void TestRSAEncryption()
        {
            Console.WriteLine("\n--- RSA加密功能测试 ---");

            try
            {
                var keyPair = RSAUtil.GenerateKeyPair(2048);
                var publicKey = (Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters)keyPair.Public;
                var privateKey = (Org.BouncyCastle.Crypto.Parameters.RsaPrivateCrtKeyParameters)keyPair.Private;

                string testData = "RSA加密测试数据";

                // 测试PKCS1填充
                string encryptedPKCS1 = RSAUtil.Encrypt(testData, publicKey, RSAUtil.RSAPadding.PKCS1);
                string decryptedPKCS1 = RSAUtil.Decrypt(encryptedPKCS1, privateKey, RSAUtil.RSAPadding.PKCS1);
                Console.WriteLine($"PKCS1填充: {(testData == decryptedPKCS1 ? "成功" : "失败")}");

                // 测试OAEP填充
                string encryptedOAEP = RSAUtil.Encrypt(testData, publicKey, RSAUtil.RSAPadding.OAEP);
                string decryptedOAEP = RSAUtil.Decrypt(encryptedOAEP, privateKey, RSAUtil.RSAPadding.OAEP);
                Console.WriteLine($"OAEP填充: {(testData == decryptedOAEP ? "成功" : "失败")}");

                // 测试Base64输出格式
                string base64Encrypted = RSAUtil.Encrypt(testData, publicKey, RSAUtil.RSAPadding.PKCS1, RSAUtil.RSAKeyFormat.Base64);
                string base64Decrypted = RSAUtil.Decrypt(base64Encrypted, privateKey, RSAUtil.RSAPadding.PKCS1, RSAUtil.RSAKeyFormat.Base64);
                Console.WriteLine($"Base64格式: {(testData == base64Decrypted ? "成功" : "失败")}");

                // 测试Hex输出格式
                string hexEncrypted = RSAUtil.Encrypt(testData, publicKey, RSAUtil.RSAPadding.PKCS1, RSAUtil.RSAKeyFormat.Hex);
                string hexDecrypted = RSAUtil.Decrypt(hexEncrypted, privateKey, RSAUtil.RSAPadding.PKCS1, RSAUtil.RSAKeyFormat.Hex);
                Console.WriteLine($"Hex格式: {(testData == hexDecrypted ? "成功" : "失败")}");

                // 测试不同编码
                var encodings = new[] {
                    ("UTF-8", Encoding.UTF8),
                    ("GBK", Encoding.GetEncoding("GBK")),
                    ("Unicode", Encoding.Unicode)
                };

                foreach (var (name, encoding) in encodings)
                {
                    try
                    {
                        string chineseText = "中文测试内容";
                        string encryptedChinese = RSAUtil.Encrypt(chineseText, publicKey, RSAUtil.RSAPadding.PKCS1, RSAUtil.RSAKeyFormat.Base64, encoding);
                        string decryptedChinese = RSAUtil.Decrypt(encryptedChinese, privateKey, RSAUtil.RSAPadding.PKCS1, RSAUtil.RSAKeyFormat.Base64, encoding);
                        Console.WriteLine($"{name}编码: {(chineseText == decryptedChinese ? "成功" : "失败")}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"{name}编码: 失败 ({ex.Message})");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"加密功能测试失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 测试RSA签名功能
        /// </summary>
        public static void TestRSASignature()
        {
            Console.WriteLine("\n--- RSA签名功能测试 ---");

            try
            {
                var keyPair = RSAUtil.GenerateKeyPair(2048);
                var publicKey = (Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters)keyPair.Public;
                var privateKey = (Org.BouncyCastle.Crypto.Parameters.RsaPrivateCrtKeyParameters)keyPair.Private;

                string testData = "RSA签名测试数据";

                // 测试不同签名算法
                var algorithms = new[] {
                    RSAUtil.SignatureAlgorithm.SHA1withRSA,
                    RSAUtil.SignatureAlgorithm.SHA256withRSA,
                    RSAUtil.SignatureAlgorithm.SHA384withRSA,
                    RSAUtil.SignatureAlgorithm.SHA512withRSA,
                    RSAUtil.SignatureAlgorithm.MD5withRSA
                };

                foreach (var algorithm in algorithms)
                {
                    string signature = RSAUtil.Sign(testData, privateKey, algorithm);
                    bool isValid = RSAUtil.Verify(testData, signature, publicKey, algorithm);
                    bool isInvalid = RSAUtil.Verify("错误数据", signature, publicKey, algorithm);

                    Console.WriteLine($"{algorithm}: 正确验签={isValid}, 错误验签={!isInvalid}");
                }

                // 测试不同输出格式
                string base64Signature = RSAUtil.Sign(testData, privateKey, RSAUtil.SignatureAlgorithm.SHA256withRSA, RSAUtil.RSAKeyFormat.Base64);
                string hexSignature = RSAUtil.Sign(testData, privateKey, RSAUtil.SignatureAlgorithm.SHA256withRSA, RSAUtil.RSAKeyFormat.Hex);

                bool base64Valid = RSAUtil.Verify(testData, base64Signature, publicKey, RSAUtil.SignatureAlgorithm.SHA256withRSA, RSAUtil.RSAKeyFormat.Base64);
                bool hexValid = RSAUtil.Verify(testData, hexSignature, publicKey, RSAUtil.SignatureAlgorithm.SHA256withRSA, RSAUtil.RSAKeyFormat.Hex);

                Console.WriteLine($"Base64签名格式: {base64Valid}");
                Console.WriteLine($"Hex签名格式: {hexValid}");

                // 测试字节数组接口
                byte[] dataBytes = Encoding.UTF8.GetBytes(testData);
                byte[] signatureBytes = RSAUtil.Sign(dataBytes, privateKey);
                bool bytesValid = RSAUtil.Verify(dataBytes, signatureBytes, publicKey);
                Console.WriteLine($"字节数组接口: {bytesValid}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"签名功能测试失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 测试RSA证书功能
        /// </summary>
        public static void TestRSACertificate()
        {
            Console.WriteLine("\n--- RSA证书功能测试 ---");

            try
            {
                var keyPair = RSAUtil.GenerateKeyPair(2048);

                // 生成自签名证书
                string subject = "CN=Test Certificate, O=Test Organization, C=CN";
                DateTime validFrom = DateTime.Now;
                DateTime validTo = DateTime.Now.AddYears(1);

                var certificate = RSAUtil.GenerateSelfSignedCertificate(keyPair, subject, validFrom, validTo);
                Console.WriteLine("自签名证书生成: 成功");
                Console.WriteLine($"  主题: {certificate.Subject}");
                Console.WriteLine($"  有效期: {certificate.NotBefore:yyyy-MM-dd} - {certificate.NotAfter:yyyy-MM-dd}");
                Console.WriteLine($"  包含私钥: {certificate.HasPrivateKey}");

                // 导出证书为PEM格式
                string certPem = RSAUtil.ExportCertificateToPem(certificate);
                Console.WriteLine($"PEM证书导出: {(certPem.Contains("BEGIN CERTIFICATE") ? "成功" : "失败")}");

                // 从证书导出密钥
                string publicKeyFromCert = RSAUtil.ExportPublicKeyFromCertificate(certificate);
                string privateKeyFromCert = RSAUtil.ExportPrivateKeyFromCertificate(certificate);
                Console.WriteLine("证书密钥导出: 成功");

                // 使用导出的密钥进行功能测试
                var publicKey = RSAUtil.ParsePublicKeyFromPem(publicKeyFromCert);
                var privateKey = RSAUtil.ParsePrivateKeyFromPem(privateKeyFromCert);

                string testData = "证书测试数据";
                string encrypted = RSAUtil.Encrypt(testData, publicKey);
                string decrypted = RSAUtil.Decrypt(encrypted, privateKey);

                Console.WriteLine($"证书密钥功能验证: {(testData == decrypted ? "成功" : "失败")}");

                certificate?.Dispose();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"证书功能测试失败: {ex.Message}");
            }
        }

        #endregion

        #region 国密SM2测试

        public static void SM2Test()
        {
            #region 证书生成测试

            Console.WriteLine("--------------国密SM2证书生成测试---------------");
            // 使用新生成的密钥对进行测试，确保结果的通用性
            var keyPair = SM2Util.GenerateKeyPair();
            var publicKey = (Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters)keyPair.Public;
            var privateKey = (Org.BouncyCastle.Crypto.Parameters.ECPrivateKeyParameters)keyPair.Private;
            // 完整格式（当前的长格式）
            string fullPublicKey = SM2Util.PublicKeyToBase64(publicKey);
            string fullPrivateKey = SM2Util.PrivateKeyToBase64(privateKey);

            // 原始格式（较短格式）
            string rawPublicKey = SM2Util.PublicKeyToRawBase64(publicKey);
            string rawPrivateKey = SM2Util.PrivateKeyToRawBase64(privateKey);
            Console.WriteLine($"完整公钥: {fullPublicKey}");
            Console.WriteLine($"原始公钥: {rawPublicKey}");
            Console.WriteLine($"完整公钥长度: {fullPublicKey.Length}");
            Console.WriteLine($"原始公钥长度: {rawPublicKey.Length}");

            Console.WriteLine($"完整私钥: {fullPrivateKey}");
            Console.WriteLine($"原始私钥: {rawPrivateKey}");
            Console.WriteLine($"完整私钥长度: {fullPrivateKey.Length}");  
            Console.WriteLine($"原始私钥长度: {rawPrivateKey.Length}");

            #endregion

            #region 国密SM2加解密测试

            Console.WriteLine("\n--------------国密SM2非对称加密算法测试---------------");
            string plainText = "国密SM2非对称加密算法测试";
            Console.WriteLine($"原文: \"{plainText}\"");

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

        #endregion

        #region 国密SM3和SM4测试

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
            string randomKey = SM4Util.GenerateKey(SM4Util.FormatType.Base64);
            Console.WriteLine("随机密钥：" + randomKey);
            string randomIV = SM4Util.GenerateIV(SM4Util.FormatType.Base64);
            Console.WriteLine("随机IV：" + randomIV);

            #endregion
        }

        #endregion
    }
}
