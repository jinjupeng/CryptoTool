# RSA������ʵ��˵��

## ����

����ʵ����һ������������RSA������ `RSAUtil`������ `.NET Standard 2.1` ��ܣ�֧����Կ���ɡ���ʽת�����ӽ��ܡ�ǩ����ǩ��֤�鴦����������ܡ�

## ��Ҫ��������

### 1. ��Կ����
- **֧����Կ����**��1024��2048��4096λ
- **��Կ�������**��PEM��Base64��Hex
- **��Կ��ʽ**��PKCS#1��PKCS#8
- **��Կ��ת**��֧��PKCS#1��PKCS#8��ʽ����ת��

### 2. �ӽ��ܹ���
- **��䷽ʽ**��PKCS#1��OAEP��NoPadding
- **�����ʽ**��String��Base64��Hex
- **�����ʽ**��Base64��Hex
- **�ַ���֧��**��UTF-8��GBK��Unicode��

### 3. ǩ����ǩ
- **֧���㷨**��
  - SHA1withRSA
  - SHA256withRSA (�Ƽ�)
  - SHA384withRSA
  - SHA512withRSA
  - MD5withRSA
- **���������ʽ**��֧��String��Base64��Hex���ֽ�����
- **�ַ���֧��**��UTF-8��GBK��

### 4. ֤�鴦��
- **������ǩ��֤��**��֧���Զ������⡢��Ч�ں�ǩ���㷨
- **֤�鵼�뵼��**��֧��PEM��ʽ���뵼��
- **��֤����ȡ��Կ**��֧�ִ�X509֤������ȡ��Կ��˽Կ

### 5. ������
- **���ݾɽӿ�**�����ֶ�ԭ�нӿڵļ�����
- **RSA����ö��**��֧��RSA��RSA2��������

## ��ṹ˵��

### ����ö��
```csharp
public enum RSAKeyFormat { PKCS1, PKCS8 }        // ��Կ��ʽ
public enum RSAPadding { PKCS1, OAEP, NoPadding } // ��䷽ʽ
public enum OutputFormat { PEM, Base64, Hex }     // �����ʽ
public enum InputFormat { String, Base64, Hex }   // �����ʽ
public enum SignatureAlgorithm { SHA1withRSA, SHA256withRSA, SHA384withRSA, SHA512withRSA, MD5withRSA } // ǩ���㷨
public enum RSAType { RSA, RSA2 }                 // RSA���ͣ������ݣ�
```

### ��Ҫ����

#### ��Կ����
```csharp
// ������Կ��
AsymmetricCipherKeyPair GenerateKeyPair(int keySize = 2048)

// ���ɹ�Կ�ַ���
string GeneratePublicKeyString(RsaKeyParameters publicKey, OutputFormat format, RSAKeyFormat keyFormat)

// ����˽Կ�ַ���
string GeneratePrivateKeyString(RsaPrivateCrtKeyParameters privateKey, OutputFormat format, RSAKeyFormat keyFormat)
```

#### ��ʽת��
```csharp
// PEM��ʽת��
string PublicKeyToPem(RsaKeyParameters publicKey, RSAKeyFormat keyFormat)
string PrivateKeyToPem(RsaPrivateCrtKeyParameters privateKey, RSAKeyFormat keyFormat)

// Base64��ʽת��
string PublicKeyToBase64(RsaKeyParameters publicKey, RSAKeyFormat keyFormat)
string PrivateKeyToBase64(RsaPrivateCrtKeyParameters privateKey, RSAKeyFormat keyFormat)

// Hex��ʽת��
string PublicKeyToHex(RsaKeyParameters publicKey, RSAKeyFormat keyFormat)
string PrivateKeyToHex(RsaPrivateCrtKeyParameters privateKey, RSAKeyFormat keyFormat)

// PKCS��ʽ��ת
string ConvertPkcs1ToPkcs8(string pkcs1Key, bool isPrivateKey, InputFormat inputFormat, OutputFormat outputFormat)
string ConvertPkcs8ToPkcs1(string pkcs8Key, bool isPrivateKey, InputFormat inputFormat, OutputFormat outputFormat)
```

#### ��Կ����
```csharp
// �Ӹ��ָ�ʽ������Կ
RsaKeyParameters ParsePublicKeyFromPem(string pemKey)
RsaKeyParameters ParsePublicKeyFromBase64(string base64Key, RSAKeyFormat keyFormat)
RsaKeyParameters ParsePublicKeyFromHex(string hexKey, RSAKeyFormat keyFormat)
RsaPrivateCrtKeyParameters ParsePrivateKeyFromPem(string pemKey)
RsaPrivateCrtKeyParameters ParsePrivateKeyFromBase64(string base64Key, RSAKeyFormat keyFormat)
RsaPrivateCrtKeyParameters ParsePrivateKeyFromHex(string hexKey, RSAKeyFormat keyFormat)
```

#### �ӽ���
```csharp
// �ַ����ӽ���
string Encrypt(string plaintext, RsaKeyParameters publicKey, RSAPadding padding, OutputFormat outputFormat, Encoding encoding)
string Decrypt(string ciphertext, RsaPrivateCrtKeyParameters privateKey, RSAPadding padding, InputFormat inputFormat, Encoding encoding)

// �ֽ�����ӽ���
byte[] Encrypt(byte[] plaintext, RsaKeyParameters publicKey, RSAPadding padding)
byte[] Decrypt(byte[] ciphertext, RsaPrivateCrtKeyParameters privateKey, RSAPadding padding)
```

#### ǩ����ǩ
```csharp
// �ַ���ǩ����ǩ
string Sign(string data, RsaPrivateCrtKeyParameters privateKey, SignatureAlgorithm algorithm, OutputFormat outputFormat, Encoding encoding)
bool Verify(string data, string signature, RsaKeyParameters publicKey, SignatureAlgorithm algorithm, InputFormat inputFormat, Encoding encoding)

// �ֽ�����ǩ����ǩ
byte[] Sign(byte[] data, RsaPrivateCrtKeyParameters privateKey, SignatureAlgorithm algorithm)
bool Verify(byte[] data, byte[] signature, RsaKeyParameters publicKey, SignatureAlgorithm algorithm)
```

#### ֤�鴦��
```csharp
// ������ǩ��֤��
X509Certificate2 GenerateSelfSignedCertificate(AsymmetricCipherKeyPair keyPair, string subject, DateTime validFrom, DateTime validTo, SignatureAlgorithm algorithm)

// ��֤�鵼����Կ
string ExportPublicKeyFromCertificate(X509Certificate2 certificate, OutputFormat format, RSAKeyFormat keyFormat)
string ExportPrivateKeyFromCertificate(X509Certificate2 certificate, OutputFormat format, RSAKeyFormat keyFormat)

// ����֤��
string ExportCertificateToPem(X509Certificate2 certificate)
```

## ʹ��ʾ��

### ������Կ���ɺͼӽ���
```csharp
// ����2048λ��Կ��
var keyPair = RSAUtil.GenerateKeyPair(2048);
var publicKey = (RsaKeyParameters)keyPair.Public;
var privateKey = (RsaPrivateCrtKeyParameters)keyPair.Private;

// ����
string plaintext = "Hello RSA!";
string encrypted = RSAUtil.Encrypt(plaintext, publicKey);

// ����
string decrypted = RSAUtil.Decrypt(encrypted, privateKey);
```

### ǩ����ǩʾ��
```csharp
string data = "��Ҫǩ��������";

// ǩ��
string signature = RSAUtil.Sign(data, privateKey, RSAUtil.SignatureAlgorithm.SHA256withRSA);

// ��ǩ
bool isValid = RSAUtil.Verify(data, signature, publicKey, RSAUtil.SignatureAlgorithm.SHA256withRSA);
```

### ��Կ��ʽת��ʾ��
```csharp
// ����PEM��ʽ��Կ
string pemPublicKey = RSAUtil.GeneratePublicKeyString(publicKey, RSAUtil.OutputFormat.PEM, RSAUtil.RSAKeyFormat.PKCS1);

// ת��ΪPKCS8��ʽ
string pkcs8PublicKey = RSAUtil.ConvertPkcs1ToPkcs8(pemPublicKey, false);
```

### ֤������ʾ��
```csharp
// ������ǩ��֤��
var certificate = RSAUtil.GenerateSelfSignedCertificate(
    keyPair, 
    "CN=Test Certificate, O=Test Organization, C=CN",
    DateTime.Now,
    DateTime.Now.AddYears(1)
);

// ����֤��PEM��ʽ
string certPem = RSAUtil.ExportCertificateToPem(certificate);
```

## ������

### .NET Standard 2.1 ֧��
- ��ȫ���� `.NET Standard 2.1` ���
- ʹ�� BouncyCastle ���ܿ��ṩ��ƽ̨֧��
- ֧���ִ� .NET Ӧ�ó���

### ������
- ������ԭ�еĽӿڷ�����ȷ�����д���ļ�����
- ֧�־ɰ汾�� `RSAType` ö�٣�RSA/RSA2��
- �ṩ�˼��ݵ� `CreateRSAKey`��`EncryptByRSA`��`DecryptByRSA` �ȷ���

## ��ȫ����

1. **��Կ����**���Ƽ�ʹ��2048λ����߳��ȵ���Կ
2. **ǩ���㷨**���Ƽ�ʹ��SHA256withRSA�����ǿ�ȵ��㷨
3. **��䷽ʽ**��������Ӧ���Ƽ�ʹ��OAEP��䣬�ṩ���ߵİ�ȫ��
4. **��Կ����**��˽ԿӦ�ð�ȫ�洢������Ӳ�����ڴ�����
5. **֤����֤**��������������ʹ��֤��ʱӦ�ý���������֤������֤

## ���Ը���

ʵ���������Ĳ���������������
- �������ܲ���
- ��Կ��ʽת������
- �ӽ��ܹ��ܲ���
- ǩ����ǩ����
- ֤�鴦�����
- ���ʽ֧�ֲ���
- �ַ��������Բ���
- .NET Standard 2.1�����Բ���

���в��������������� `Program.cs` �� `RSATest()` �����У�����ͨ�����п���̨Ӧ�ó��������֤��

## �ܽ�

��RSA������ʵ����������RSA���ܹ��ܣ�֧���ִ�����ѧ���ʵ����ͬʱ�����������ԣ������ڸ���.NETӦ�ó�����