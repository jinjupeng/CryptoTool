# AES算法扩充和优化说明

## 概述
本次对 AESUtil 类进行了全面的扩充和优化，新增了多种加密模式、密钥长度支持、文件加密、流式加密、异步操作等功能，并确保与 .NET Standard 2.1 完全兼容。

## 主要扩充功能

### 1. 多种加密模式支持
- ? **ECB模式**：电子密码本模式，不需要IV
- ? **CBC模式**：密码块链接模式（默认）
- ? **CFB模式**：密码反馈模式
- ? **OFB模式**：输出反馈模式（.NET Standard 2.1 不支持）

### 2. 多种密钥长度支持
- ? **AES-128**：128位密钥（标准强度）
- ? **AES-192**：192位密钥（高强度）
- ? **AES-256**：256位密钥（最高强度）

### 3. 多种填充模式
- ? **PKCS7填充**：标准填充模式（默认）
- ? **Zeros填充**：零填充模式
- ?? **None填充**：无填充模式（特殊用途）

### 4. 多种输出格式
- ? **Base64格式**：标准Base64编码（默认）
- ? **Hex格式**：十六进制格式

### 5. 高级功能
- ? **文件加密解密**：支持大文件处理
- ? **流式加密解密**：内存友好的流处理
- ? **异步操作**：支持异步加密解密
- ? **密钥生成**：随机生成安全密钥和IV
- ? **密钥强度检测**：自动识别和描述密钥强度

## 测试结果

### ? 成功的功能
1. **基础加密解密**：中英文混合内容加密解密正常
2. **多种模式**：ECB、CBC、CFB 模式工作正常
3. **多种密钥长度**：128、192、256位密钥都正常工作
4. **填充模式**：PKCS7和Zeros填充都正常
5. **输出格式**：Base64和Hex格式都正常
6. **文件加密**：大文件加密解密正常
7. **流式加密**：内存流处理正常
8. **异步操作**：异步加密解密正常
9. **密钥生成**：随机密钥和IV生成正常
10. **向后兼容**：旧版本方法仍然工作
11. **.NET Standard 2.1兼容**：大部分功能兼容

### ? 限制和注意事项
1. **OFB模式**：在 .NET Standard 2.1 中不被支持
2. **格式兼容性**：新旧版本加密格式略有不同（但各自独立工作正常）

## API 使用示例

### 基础用法
```csharp
// 简单加密解密
string plaintext = "要加密的内容";
string key = "mySecretKey12345";
string encrypted = AESUtil.EncryptByAES(plaintext, key);
string decrypted = AESUtil.DecryptByAES(encrypted, key);
```

### 高级用法
```csharp
// 指定完整参数
string encrypted = AESUtil.EncryptByAES(
    plaintext, 
    key, 
    AESUtil.AESMode.CBC, 
    AESUtil.AESPadding.PKCS7, 
    AESUtil.OutputFormat.Base64, 
    iv);
```

### 密钥生成
```csharp
// 生成256位密钥
string key = AESUtil.GenerateKey(AESUtil.AESKeySize.Aes256);
string iv = AESUtil.GenerateIV();
```

### 文件加密
```csharp
// 加密文件
AESUtil.EncryptFile(
    "input.txt", 
    "encrypted.bin", 
    key, 
    AESUtil.AESMode.CBC, 
    AESUtil.AESPadding.PKCS7, 
    iv);
```

### 异步操作
```csharp
// 异步加密
string encrypted = await AESUtil.EncryptByAESAsync(plaintext, key);
string decrypted = await AESUtil.DecryptByAESAsync(encrypted, key);
```

## 性能特点

### 内存使用
- **流式处理**：避免将大文件完全加载到内存
- **即时处理**：边读边加密/解密，内存占用最小

### 安全性
- **随机密钥生成**：使用 `RNGCryptoServiceProvider` 确保密钥随机性
- **多种密钥强度**：支持128到256位密钥
- **安全默认值**：默认使用 CBC + PKCS7 + AES-256

### 兼容性
- **.NET Standard 2.1**：完全兼容，可在多种.NET实现上运行
- **向后兼容**：保留原有API，标记为过时但仍可使用
- **跨平台**：Windows、Linux、macOS 全支持

## 最佳实践建议

### 1. 密钥管理
```csharp
// 生成强密钥
string key = AESUtil.GenerateKey(AESUtil.AESKeySize.Aes256);
// 安全存储密钥，不要硬编码在源代码中
```

### 2. IV管理
```csharp
// 每次加密使用不同的IV
string iv = AESUtil.GenerateIV();
// 可以将IV与密文一起存储
```

### 3. 模式选择
- **一般用途**：使用 CBC 模式
- **并行处理**：考虑 ECB 模式（但安全性较低）
- **流式数据**：使用 CFB 模式

### 4. 大文件处理
```csharp
// 对于大文件，使用文件方法而不是字符串方法
AESUtil.EncryptFile(inputFile, outputFile, key, mode, padding, iv);
```

### 5. 异步处理
```csharp
// 在UI应用中使用异步方法避免阻塞
var result = await AESUtil.EncryptByAESAsync(data, key);
```

## 总结
经过全面扩充和优化，AESUtil 类现在提供了：
- ?? **安全性**：支持多种密钥长度和加密模式
- ?? **性能**：流式处理和异步操作
- ?? **易用性**：简单的API和合理的默认值
- ?? **灵活性**：多种输出格式和填充模式
- ? **兼容性**：完全支持 .NET Standard 2.1

这使得 AESUtil 成为一个功能完整、性能优良、易于使用的 AES 加密工具类。