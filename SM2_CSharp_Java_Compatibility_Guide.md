# SM2 C#��Java��������ָ��

## ����

���ĵ�˵���������C#��Java֮��ʵ��SM2�����㷨����ȫ���ݣ��ر��ǽ�����ĸ�ʽ�����Ժ�ǩ����ʽת���Ĺؼ����⡣

## ���ļ���������

### 1. ���ĸ�ʽ���� (0x04ǰ׺����)

����C#��Java BouncyCastle��֮������Ҫ�ļ��������⣺

**����������**
- **.NET BouncyCastle**: ���ɵ�����C1���ְ���0x04ǰ׺��65�ֽ�δѹ���㣩
- **Java BouncyCastle**: ���ɵ�����C1���ֲ�����0x04ǰ׺��64�ֽ����꣩

**���Ľṹ�Աȣ�**
```
.NET���ĸ�ʽ��  0x04 + X(32�ֽ�) + Y(32�ֽ�) + C2(�䳤) + C3(32�ֽ�)
Java���ĸ�ʽ��       X(32�ֽ�) + Y(32�ֽ�) + C2(�䳤) + C3(32�ֽ�)
```

### 2. �������

#### C#�˽������

```csharp
// ����Java��������
string javaCompatibleCiphertext = SM2Util.EncryptForJava(plainText, publicKey);

// ����Java����
string decryptedText = SM2Util.DecryptFromJavaToString(javaCiphertext, privateKey);

// ���ܽ��ܣ��Զ�����ʽ��
string smartDecryptText = SM2Util.SmartDecryptToString(ciphertext, privateKey);

// ��ʽ���
bool isJavaFormat = SM2Util.IsJavaFormat(ciphertextBytes, SM2CipherFormat.C1C3C2);
```

#### Java�˽������

```java
// ����C#��������
String dotNetCompatibleCiphertext = encryptForDotNet(plainText, publicKey);

// ����C#����
String decryptedText = decryptFromDotNet(csharpCiphertext, privateKey);

// ���ܽ��ܣ��Զ�����ʽ��
String smartDecryptText = smartDecrypt(ciphertext, privateKey);

// ��ʽ���
boolean isDotNetFormat = isDotNetFormat(ciphertextBytes);
```

## ǩ����ʽ˵��

### 1. ASN.1 DER��ʽ
- **��;**: BouncyCastleĬ�ϸ�ʽ����׼������ǩ����ʽ
- **�ṹ**: `SEQUENCE { r INTEGER, s INTEGER }`
- **�ص�**: �䳤���룬�������ͺͳ�����Ϣ
- **������**: ������ȫ����

### 2. RS��ʽ  
- **��;**: �̶����ȸ�ʽ�����ڴ洢�ʹ���
- **�ṹ**: `r || s` (r��s��32�ֽ�)
- **�ص�**: �̶�64�ֽڳ��ȣ��޶��������Ϣ
- **������**: ��Ҫ��ȷ����BigInteger�ķ���λ

## ����������ʵ��

### C#������ʾ��

```csharp
public static void TestJavaCompatibility()
{
    // 1. ������Կ��
    var keyPair = SM2Util.GenerateKeyPair();
    var publicKey = (ECPublicKeyParameters)keyPair.Public;
    var privateKey = (ECPrivateKeyParameters)keyPair.Private;
    
    string plainText = "��������";
    
    // 2. ���ܼ����Բ���
    
    // ��׼C#����
    string csharpCiphertext = SM2Util.Encrypt(plainText, publicKey);
    
    // Java���ݼ��ܣ��Ƴ�0x04ǰ׺��
    string javaCompatibleCiphertext = SM2Util.EncryptForJava(plainText, publicKey);
    
    // 3. ���ܼ����Բ���
    
    // ���ܱ�׼C#����
    string decrypted1 = SM2Util.DecryptToString(csharpCiphertext, privateKey);
    
    // ����Java��ʽ����
    string decrypted2 = SM2Util.DecryptFromJavaToString(javaCompatibleCiphertext, privateKey);
    
    // ���ܽ��ܣ��Զ�����ʽ��
    string decrypted3 = SM2Util.SmartDecryptToString(csharpCiphertext, privateKey);
    string decrypted4 = SM2Util.SmartDecryptToString(javaCompatibleCiphertext, privateKey);
    
    // 4. ǩ�������Բ���
    byte[] data = Encoding.UTF8.GetBytes(plainText);
    
    // ASN.1��ʽǩ��
    string asn1Signature = SM2Util.SignSm3WithSm2(data, privateKey, SM2SignatureFormat.ASN1);
    
    // RS��ʽǩ��
    string rsSignature = SM2Util.SignSm3WithSm2(data, privateKey, SM2SignatureFormat.RS);
    
    // ��ʽת��
    string convertedRs = SM2Util.ConvertHexAsn1ToHexRs(asn1Signature);
    string convertedAsn1 = SM2Util.ConvertHexRsToHexAsn1(rsSignature);
    
    // ��֤ǩ��
    bool valid1 = SM2Util.VerifySm3WithSm2(data, asn1Signature, publicKey, SM2SignatureFormat.ASN1);
    bool valid2 = SM2Util.VerifySm3WithSm2(data, rsSignature, publicKey, SM2SignatureFormat.RS);
}
```

### Java������ʾ��

```java
public static void testCSharpCompatibility() throws Exception {
    // 1. ������Կ�ԣ�ʹ����C#��ͬ����Կ��
    String hexPublicKey = "04..."; // ��C#�˻�ȡ
    String hexPrivateKey = "...";  // ��C#�˻�ȡ
    
    ECPublicKeyParameters publicKey = createPublicKeyFromHex(hexPublicKey);
    ECPrivateKeyParameters privateKey = createPrivateKeyFromHex(hexPrivateKey);
    
    String plainText = "��������";
    
    // 2. ���ܼ����Բ���
    
    // Java��׼����
    SM2Engine engine = new SM2Engine();
    engine.init(true, new ParametersWithRandom(publicKey, new SecureRandom()));
    byte[] javaStandardCiphertext = engine.processBlock(plainText.getBytes("UTF-8"), 0, plainText.length());
    
    // C#���ݼ��ܣ����0x04ǰ׺��
    String csharpCompatibleCiphertext = encryptForDotNet(plainText, publicKey);
    
    // 3. ���ܼ����Բ���
    
    // ����Java��׼����
    engine.init(false, privateKey);
    byte[] decrypted1 = engine.processBlock(javaStandardCiphertext, 0, javaStandardCiphertext.length);
    
    // ����C#��ʽ����
    String decrypted2 = decryptFromDotNet(csharpCompatibleCiphertext, privateKey);
    
    // ���ܽ���
    String decrypted3 = smartDecrypt(Base64.toBase64String(javaStandardCiphertext), privateKey);
    String decrypted4 = smartDecrypt(csharpCompatibleCiphertext, privateKey);
    
    // 4. ǩ�������Բ���
    byte[] data = plainText.getBytes("UTF-8");
    
    // ASN.1��ʽǩ��
    String asn1Signature = signSM2Asn1(data, privateKey);
    
    // RS��ʽǩ��
    String rsSignature = signSM2Rs(data, privateKey);
    
    // ��ʽת��
    byte[] convertedRs = convertAsn1ToRs(Hex.decode(asn1Signature));
    byte[] convertedAsn1 = convertRsToAsn1(Hex.decode(rsSignature));
    
    // ��֤ǩ��
    boolean valid1 = verifySM2(data, asn1Signature, publicKey, false);
    boolean valid2 = verifySM2(data, rsSignature, publicKey, true);
}
```

## ���ʵ��

### 1. ��������

1. **ͳһ�ӿ����**��
   ```csharp
   // C#�ˣ��ṩJava���ݷ���
   string EncryptForJava(string plainText, ECPublicKeyParameters publicKey);
   string DecryptFromJava(string ciphertext, ECPrivateKeyParameters privateKey);
   ```

   ```java
   // Java�ˣ��ṩC#���ݷ���
   String encryptForDotNet(String plainText, ECPublicKeyParameters publicKey);
   String decryptFromDotNet(String ciphertext, ECPrivateKeyParameters privateKey);
   ```

2. **���ܴ���**��
   ```csharp
   // �Զ�������ĸ�ʽ
   string SmartDecrypt(string ciphertext, ECPrivateKeyParameters privateKey);
   ```

3. **��ʽ��֤**��
   ```csharp
   bool IsJavaFormat(byte[] ciphertext, SM2CipherFormat format);
   ```

### 2. ������

```csharp
try
{
    string result = SM2Util.SmartDecryptToString(ciphertext, privateKey);
}
catch (ArgumentException ex)
{
    // �����ʽ����
    Console.WriteLine($"���ĸ�ʽ����: {ex.Message}");
}
catch (CryptographicException ex)
{
    // ������ܴ���
    Console.WriteLine($"����ʧ��: {ex.Message}");
}
```

### 3. �����Ż�

1. **�����ظ�ת��**���ڽӿڲ�ͳһ��ʽ����������ʱת��
2. **������Կ����**�������ظ�������Կ
3. **��������**�����ڴ������ݣ�����������ʽת��

## ������֤

### 1. ��Ԫ����

```csharp
[Test]
public void TestCrossPlatformCompatibility()
{
    var keyPair = SM2Util.GenerateKeyPair();
    var publicKey = (ECPublicKeyParameters)keyPair.Public;
    var privateKey = (ECPrivateKeyParameters)keyPair.Private;
    
    string plainText = "��ƽ̨�����Բ���";
    
    // C# -> Java ������
    string javaCompatibleCiphertext = SM2Util.EncryptForJava(plainText, publicKey);
    string decrypted1 = SM2Util.DecryptFromJavaToString(javaCompatibleCiphertext, privateKey);
    Assert.AreEqual(plainText, decrypted1);
    
    // ���ܽ��ܲ���
    string smartDecrypted = SM2Util.SmartDecryptToString(javaCompatibleCiphertext, privateKey);
    Assert.AreEqual(plainText, smartDecrypted);
}
```

### 2. ���ɲ���

1. **��Կһ����**��ȷ������ʹ����ͬ����Կ
2. **����һ����**��ȷ������ʹ����ͬ�Ĳ�������
3. **��ʽ��֤**����֤ת����ĸ�ʽ��ȷ��
4. **������֤**����֤���ܽ��ܹ�������

## ��������

### Q1: Ϊʲô��Ҫ����0x04ǰ׺��
A1: ������Բ���ߵ�ı����׼���졣0x04��ʾδѹ�����ʽ����ͬ��BouncyCastleʵ�ֶԴ˴���ͬ��

### Q2: ���ȷ����ƽ̨�����ԣ�
A2: 
- ʹ��ר�ŵļ����Է�����EncryptForJava/DecryptFromJava��
- ʵ�����ܼ����Զ�ת��
- ���г�ֵļ��ɲ���

### Q3: ����Ӱ����Σ�
A3: ��ʽת�������ܿ�����С����Ҫ�����鸴�ƣ����������ڼܹ����ʱͳһ��ʽ��׼��

### Q4: ��ε��Լ��������⣿
A4: 
- ������ĳ��Ȳ��죨���1�ֽڣ�
- ��֤��һ���ֽ��Ƿ�Ϊ0x04
- ʹ��ʮ�����ƹ��߱ȶ����Ľṹ

## �汾��ʷ

- v1.0: ��ʼ�汾��������RS��ASN.1��ת
- v1.1: ����Java�������Ż�
- v1.2: ���ƴ��������֤����
- v2.0: **������ĸ�ʽ�����Դ���0x04ǰ׺���⣩**
- v2.1: �������ܼ����Զ�ת������