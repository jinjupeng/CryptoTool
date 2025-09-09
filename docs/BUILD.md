# CryptoTool ����˵��

## �Զ��������ʹ��

����Ŀ֧��ͨ�� GitHub Actions �Զ������ʹ����֧�����¸�ʽ��
- `.exe` ��ִ���ļ����԰����Ϳ�������汾��
- `.msi` Windows ��װ��
- `.zip` ѹ����

### �汾����

�汾�ŵĻ�ȡ���ȼ����£�
1. **Git��ǩ�汾**�������ʹ��� `v*.*.*` ��ʽ�ı�ǩʱ���� `v1.2.0`�������Զ�ʹ�ñ�ǩ�汾
2. **��Ŀ�ļ��汾**���� `CryptoTool.Win/CryptoTool.Win.csproj` �е� `<Version>` ���Զ�ȡ

### �Զ���������

#### �����汾����
ÿ�����͵� `master` ��֧�򴴽� Pull Request ʱ�����Զ������������õİ��������ᴴ�� GitHub Release��

#### ��ʽ�汾����
1. ������Ŀ�汾�ţ���ѡ��Ҳ����ֱ��ʹ�� Git ��ǩ�汾����
   ```xml
   <!-- �� CryptoTool.Win/CryptoTool.Win.csproj �� -->
   <Version>1.2.0</Version>
   <AssemblyVersion>1.2.0.0</AssemblyVersion>
   <FileVersion>1.2.0.0</FileVersion>
   ```

2. ���������ͱ�ǩ��
   ```bash
   git tag v1.2.0
   git push origin v1.2.0
   ```

3. GitHub Actions ���Զ���
   - �������а���ʽ
   - ���� GitHub Release
   - �ϴ����й�������

### ��������˵��

ÿ�ι��������������ļ���

#### ��ִ���ļ�
- `CryptoTool-v{version}-win-x64-SelfContained.exe` - �԰����汾�����谲װ .NET ����ʱ
- `CryptoTool-v{version}-win-x64-FrameworkDependent.exe` - ��Ҫ .NET 8 ����ʱ
- `CryptoTool.App-v{version}-win-x64.exe` - ����̨Ӧ�ó���

#### ��װ��
- `CryptoTool-v{version}-win-x64-Setup.msi` - Windows ��װ�����Զ���������Ϳ�ʼ�˵���ݷ�ʽ

#### ѹ����
- `CryptoTool-v{version}-SelfContained-Release.zip` - �԰����汾�������ļ�
- `CryptoTool-v{version}-FrameworkDependent-Release.zip` - ��������汾�������ļ�
- `CryptoTool.App-v{version}-Release.zip` - ����̨Ӧ�ó���������ļ�

## ���ع���

### ǰ������
- .NET 8 SDK
- WiX Toolset v5�����ڹ��� MSI��

### ��װ WiX Toolset
```bash
dotnet tool install --global wix --version 5.0.0
wix extension add WixToolset.UI.wixext
```

### ��������

#### ����1��ʹ���������ļ����Ƽ���
˫������ `build-msi.bat` ������������ִ�У�
```bash
build-msi.bat
```

#### ����2��ʹ�� PowerShell �ű�
```powershell
# ʹ����Ŀ�ļ��еİ汾��
./build-msi.ps1

# ָ���汾��
./build-msi.ps1 -Version "1.2.0"

# ָ������
./build-msi.ps1 -Configuration "Debug"
```

#### ����3���ֶ�����
```bash
# �����������
dotnet build CryptoTool.sln --configuration Release

# ����Ӧ��
dotnet publish CryptoTool.Win/CryptoTool.Win.csproj --configuration Release --runtime win-x64 --self-contained true --output ./publish/CryptoTool.Win-SelfContained -p:PublishSingleFile=true

# ���� MSI����Ҫ�ȴ��� WiX �����ļ���
wix build installer/CryptoTool.wxs -o CryptoTool-Setup.msi
```

## ����˵��

### GitHub Actions ����
����������λ�� `.github/workflows/dotnet-desktop.yml`������������Ҫ���裺
- �汾��⣨Git ��ǩ > ��Ŀ�ļ��汾��
- �����ù�����Debug/Release��
- MSI ������
- �Զ������� GitHub Releases

### MSI ��װ������
- ��װλ�ã�`%ProgramFiles%\CryptoTool\`
- �Զ����������ݷ�ʽ
- �Զ�������ʼ�˵���ݷ�ʽ
- ֧��������ж��

### ��Ŀ����
�ؼ�����Ŀ����λ�� `CryptoTool.Win/CryptoTool.Win.csproj`��
- �汾��Ϣ
- Ӧ�ó���ͼ��
- ��Ʒ����
- ��˾��Ϣ

## �����ų�

### WiX ��װ����
������� WiX ��ش���
```bash
# ж�ز����°�װ
dotnet tool uninstall --global wix
dotnet tool install --global wix --version 5.0.0
wix extension add WixToolset.UI.wixext
```

### ����ʧ��
1. ȷ����������������ȷ��װ
2. �����Ŀ�ļ��еİ汾�Ÿ�ʽ
3. ȷ������Ŀ¼�����ҿ�д
4. ��� WiX �����ļ��﷨

### GitHub Actions ʧ��
1. �����Ŀ�ļ��еİ汾�Ÿ�ʽ
2. ȷ����ǩ��ʽΪ `v*.*.*`
3. ��鹤����Ȩ������
4. �鿴 Actions ��־��ȡ��ϸ������Ϣ