using System;
using System.Threading.Tasks;
using CryptoTool.Algorithm.Algorithms.SM2;
using CryptoTool.Algorithm.Utils;

namespace CryptoTool.Test.Examples
{
    /// <summary>
    /// SM2密文格式转换示例
    /// </summary>
    public static class Sm2CipherFormatExample
    {
        /// <summary>
        /// 基本密文格式转换示例
        /// </summary>
        public static void BasicFormatConversionExample()
        {
            Console.WriteLine("=== SM2密文格式转换示例 ===");

            // 模拟C1C2C3格式的密文数据
            var c1c2c3Data = CreateMockC1C2C3Data();
            Console.WriteLine($"原始C1C2C3密文长度: {c1c2c3Data.Length} 字节");
            Console.WriteLine($"原始C1C2C3密文(十六进制): {Algorithm.CryptoTool.BytesToHex(c1c2c3Data, true)}");

            // 转换为C1C3C2格式
            var c1c3c2Data = Algorithm.CryptoTool.Sm2ConvertC1C2C3ToC1C3C2(c1c2c3Data);
            Console.WriteLine($"转换后C1C3C2密文长度: {c1c3c2Data.Length} 字节");
            Console.WriteLine($"转换后C1C3C2密文(十六进制): {Algorithm.CryptoTool.BytesToHex(c1c3c2Data, true)}");

            // 转换回C1C2C3格式
            var convertedBack = Algorithm.CryptoTool.Sm2ConvertC1C3C2ToC1C2C3(c1c3c2Data);
            Console.WriteLine($"转换回C1C2C3密文长度: {convertedBack.Length} 字节");
            Console.WriteLine($"转换回C1C2C3密文(十六进制): {Algorithm.CryptoTool.BytesToHex(convertedBack, true)}");

            // 验证转换是否正确
            bool isEqual = CryptoUtil.ByteArraysEqual(c1c2c3Data, convertedBack);
            Console.WriteLine($"转换验证结果: {(isEqual ? "成功" : "失败")}");
        }

        /// <summary>
        /// 密文格式检测示例
        /// </summary>
        public static void FormatDetectionExample()
        {
            Console.WriteLine("\n=== 密文格式检测示例 ===");

            // 创建C1C2C3格式密文
            var c1c2c3Data = CreateMockC1C2C3Data();
            var c1c2c3Format = Algorithm.CryptoTool.Sm2DetectCipherFormat(c1c2c3Data);
            Console.WriteLine($"C1C2C3密文检测结果: {c1c2c3Format}");

            // 转换为C1C3C2格式
            var c1c3c2Data = Algorithm.CryptoTool.Sm2ConvertC1C2C3ToC1C3C2(c1c2c3Data);
            var c1c3c2Format = Algorithm.CryptoTool.Sm2DetectCipherFormat(c1c3c2Data);
            Console.WriteLine($"C1C3C2密文检测结果: {c1c3c2Format}");

            // 验证密文数据完整性
            bool c1c2c3Valid = Algorithm.CryptoTool.Sm2ValidateCipherData(c1c2c3Data, SM2CipherFormat.C1C2C3);
            bool c1c3c2Valid = Algorithm.CryptoTool.Sm2ValidateCipherData(c1c3c2Data, SM2CipherFormat.C1C3C2);
            
            Console.WriteLine($"C1C2C3密文验证结果: {(c1c2c3Valid ? "有效" : "无效")}");
            Console.WriteLine($"C1C3C2密文验证结果: {(c1c3c2Valid ? "有效" : "无效")}");
        }

        /// <summary>
        /// 密文组件信息示例
        /// </summary>
        public static void ComponentInfoExample()
        {
            Console.WriteLine("\n=== 密文组件信息示例 ===");

            // C1C2C3格式组件信息
            var c1c2c3Data = CreateMockC1C2C3Data();
            var c1c2c3Info = Algorithm.CryptoTool.Sm2GetCipherComponentInfo(c1c2c3Data);
            Console.WriteLine($"C1C2C3格式组件信息: {c1c2c3Info}");

            // C1C3C2格式组件信息
            var c1c3c2Data = Algorithm.CryptoTool.Sm2ConvertC1C2C3ToC1C3C2(c1c2c3Data);
            var c1c3c2Info = Algorithm.CryptoTool.Sm2GetCipherComponentInfo(c1c3c2Data);
            Console.WriteLine($"C1C3C2格式组件信息: {c1c3c2Info}");
        }

        /// <summary>
        /// 异步转换示例
        /// </summary>
        public static async Task AsyncConversionExample()
        {
            Console.WriteLine("\n=== 异步密文格式转换示例 ===");

            var c1c2c3Data = CreateMockC1C2C3Data();
            Console.WriteLine($"原始C1C2C3密文长度: {c1c2c3Data.Length} 字节");

            // 异步转换为C1C3C2格式
            var c1c3c2Data = await Algorithm.CryptoTool.Sm2ConvertC1C2C3ToC1C3C2Async(c1c2c3Data);
            Console.WriteLine($"异步转换后C1C3C2密文长度: {c1c3c2Data.Length} 字节");

            // 异步转换回C1C2C3格式
            var convertedBack = await Algorithm.CryptoTool.Sm2ConvertC1C3C2ToC1C2C3Async(c1c3c2Data);
            Console.WriteLine($"异步转换回C1C2C3密文长度: {convertedBack.Length} 字节");

            // 异步检测格式
            var format = await Algorithm.CryptoTool.Sm2DetectCipherFormatAsync(convertedBack);
            Console.WriteLine($"异步检测格式结果: {format}");

            // 验证转换结果
            bool isEqual = CryptoUtil.ByteArraysEqual(c1c2c3Data, convertedBack);
            Console.WriteLine($"异步转换验证结果: {(isEqual ? "成功" : "失败")}");
        }

        /// <summary>
        /// 批量转换示例
        /// </summary>
        public static void BatchConversionExample()
        {
            Console.WriteLine("\n=== 批量密文格式转换示例 ===");

            var testData = new[]
            {
                CreateMockC1C2C3Data(),
                CreateMockC1C2C3Data(100), // 不同的C2长度
                CreateMockC1C2C3Data(200)  // 不同的C2长度
            };

            for (int i = 0; i < testData.Length; i++)
            {
                var original = testData[i];
                var converted = Algorithm.CryptoTool.Sm2ConvertC1C2C3ToC1C3C2(original);
                var convertedBack = Algorithm.CryptoTool.Sm2ConvertC1C3C2ToC1C2C3(converted);
                
                bool isEqual = CryptoUtil.ByteArraysEqual(original, convertedBack);
                Console.WriteLine($"测试数据 {i + 1}: 原始={original.Length}字节, 转换={converted.Length}字节, 验证={(isEqual ? "成功" : "失败")}");
            }
        }

        /// <summary>
        /// 错误处理示例
        /// </summary>
        public static void ErrorHandlingExample()
        {
            Console.WriteLine("\n=== 错误处理示例 ===");

            try
            {
                // 测试空数据
                Algorithm.CryptoTool.Sm2ConvertC1C2C3ToC1C3C2(null);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"空数据错误: {ex.Message}");
            }

            try
            {
                // 测试长度不足的数据
                var shortData = new byte[50]; // 长度不足
                Algorithm.CryptoTool.Sm2ConvertC1C2C3ToC1C3C2(shortData);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"长度不足错误: {ex.Message}");
            }

            try
            {
                // 测试无效格式的数据
                var invalidData = new byte[200];
                new Random().NextBytes(invalidData);
                Algorithm.CryptoTool.Sm2DetectCipherFormat(invalidData);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"无效格式错误: {ex.Message}");
            }
        }

        /// <summary>
        /// 运行所有示例
        /// </summary>
        public static async Task RunAllExamples()
        {
            try
            {
                BasicFormatConversionExample();
                FormatDetectionExample();
                ComponentInfoExample();
                await AsyncConversionExample();
                BatchConversionExample();
                ErrorHandlingExample();
                
                Console.WriteLine("\n=== 所有SM2密文格式转换示例运行完成 ===");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"示例运行出错: {ex.Message}");
            }
        }

        /// <summary>
        /// 创建模拟的C1C2C3格式密文数据
        /// </summary>
        /// <param name="c2Length">C2组件长度</param>
        /// <returns>模拟密文数据</returns>
        private static byte[] CreateMockC1C2C3Data(int c2Length = 50)
        {
            var random = new Random();
            var data = new byte[65 + c2Length + 32]; // C1(65) + C2(可变) + C3(32)
            var offset = 0;

            // C1: 椭圆曲线点 (1字节标识 + 32字节X + 32字节Y)
            data[offset] = 0x04; // 未压缩点格式标识
            offset++;
            random.NextBytes(data, offset, 32); // X坐标
            offset += 32;
            random.NextBytes(data, offset, 32); // Y坐标
            offset += 32;

            // C2: 密文数据
            random.NextBytes(data, offset, c2Length);
            offset += c2Length;

            // C3: 哈希值
            random.NextBytes(data, offset, 32);

            return data;
        }
    }

    /// <summary>
    /// 扩展方法
    /// </summary>
    public static class RandomExtensions
    {
        /// <summary>
        /// 填充指定范围的随机字节
        /// </summary>
        /// <param name="random">随机数生成器</param>
        /// <param name="buffer">缓冲区</param>
        /// <param name="offset">偏移量</param>
        /// <param name="count">数量</param>
        public static void NextBytes(this Random random, byte[] buffer, int offset, int count)
        {
            for (int i = 0; i < count; i++)
            {
                buffer[offset + i] = (byte)random.Next(0, 256);
            }
        }
    }
}
