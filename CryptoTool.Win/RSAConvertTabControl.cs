using CryptoTool.Common;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;

namespace CryptoTool.Win
{
    public partial class RSAConvertTabControl : UserControl
    {
        public event Action<string> StatusChanged;

        // 存储导入的公钥和私钥用于验证
        private string _publicKeyForValidation = string.Empty;
        private string _privateKeyForValidation = string.Empty;
        private RSAUtil.RSAKeyFormat _publicKeyFormatForValidation = RSAUtil.RSAKeyFormat.PEM;
        private RSAUtil.RSAKeyType _publicKeyTypeForValidation = RSAUtil.RSAKeyType.PKCS1;
        private RSAUtil.RSAKeyFormat _privateKeyFormatForValidation = RSAUtil.RSAKeyFormat.PEM;
        private RSAUtil.RSAKeyType _privateKeyTypeForValidation = RSAUtil.RSAKeyType.PKCS1;

        public RSAConvertTabControl()
        {
            InitializeComponent();
            InitializeDefaults();
        }

        private void InitializeDefaults()
        {
            // 初始化默认值
            comboInputKeyType.SelectedIndex = 0; // PKCS1
            comboInputFormat.SelectedIndex = 0; // PEM
            comboOutputKeyType.SelectedIndex = 1; // PKCS8
            comboOutputFormat.SelectedIndex = 0; // PEM
            radioPrivateKey.Checked = true;
            
            // 初始化验证结果标签
            labelValidationResult.Text = "验证结果: 等待验证";
            labelValidationResult.ForeColor = Color.Gray;
        }

        private void SetStatus(string message)
        {
            StatusChanged?.Invoke(message);
        }

        #region 事件处理

        private void btnImportFromFile_Click(object sender, EventArgs e)
        {
            try
            {
                using (OpenFileDialog openFileDialog = new OpenFileDialog())
                {
                    openFileDialog.Filter = "密钥文件 (*.txt;*.key;*.pem;*.pub)|*.txt;*.key;*.pem;*.pub|所有文件 (*.*)|*.*";
                    openFileDialog.Title = "导入RSA密钥文件";

                    if (openFileDialog.ShowDialog() == DialogResult.OK)
                    {
                        string content = File.ReadAllText(openFileDialog.FileName, Encoding.UTF8);
                        textInputKey.Text = content.Trim();
                        
                        // 根据文件内容自动判断密钥类型
                        AutoDetectKeyType(content);
                        
                        SetStatus("密钥文件导入成功");
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导入密钥文件失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("导入密钥文件失败");
            }
        }

        private void btnValidateKeyPair_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(_publicKeyForValidation) || string.IsNullOrEmpty(_privateKeyForValidation))
                {
                    MessageBox.Show("请先分别导入公钥和私钥进行验证！\n\n操作步骤：\n1. 导入私钥并点击「从私钥提取公钥」\n2. 或分别导入公钥和私钥文件", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }

                SetStatus("正在验证密钥对一致性...");

                bool isValid = ValidateKeyPair(_publicKeyForValidation, _privateKeyForValidation, 
                    _publicKeyFormatForValidation, _publicKeyTypeForValidation,
                    _privateKeyFormatForValidation, _privateKeyTypeForValidation);

                labelValidationResult.Text = $"验证结果: {(isValid ? "密钥对匹配" : "密钥对不匹配")}";
                labelValidationResult.ForeColor = isValid ? Color.Green : Color.Red;

                SetStatus($"密钥对验证完成 - {(isValid ? "匹配" : "不匹配")}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"密钥对验证失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                labelValidationResult.Text = "验证结果: 验证异常";
                labelValidationResult.ForeColor = Color.Red;
                SetStatus("密钥对验证失败");
            }
        }

        private void btnGetPublicKeyFromPrivate_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textInputKey.Text))
                {
                    MessageBox.Show("请先输入私钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (radioPublicKey.Checked)
                {
                    MessageBox.Show("请选择私钥类型才能提取公钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在从私钥提取公钥...");

                var inputKeyType = (RSAUtil.RSAKeyType)comboInputKeyType.SelectedIndex;
                var inputFormat = (RSAUtil.RSAKeyFormat)comboInputFormat.SelectedIndex;
                var outputKeyType = (RSAUtil.RSAKeyType)comboOutputKeyType.SelectedIndex;
                var outputFormat = (RSAUtil.RSAKeyFormat)comboOutputFormat.SelectedIndex;

                // 解析私钥
                var privateKey = (RsaPrivateCrtKeyParameters)RSAUtil.ParseKey(
                    textInputKey.Text, true, inputFormat, inputKeyType);

                // 从私钥获取公钥参数
                var publicKey = new RsaKeyParameters(false, privateKey.Modulus, privateKey.PublicExponent);

                // 生成公钥字符串
                string publicKeyString = RSAUtil.GeneratePublicKeyString(publicKey, outputFormat, outputKeyType);

                textOutputKey.Text = publicKeyString;

                // 存储密钥用于验证
                _privateKeyForValidation = textInputKey.Text;
                _privateKeyFormatForValidation = inputFormat;
                _privateKeyTypeForValidation = inputKeyType;
                _publicKeyForValidation = publicKeyString;
                _publicKeyFormatForValidation = outputFormat;
                _publicKeyTypeForValidation = outputKeyType;

                // 自动验证密钥对
                labelValidationResult.Text = "验证结果: 密钥对匹配（从私钥提取）";
                labelValidationResult.ForeColor = Color.Green;

                SetStatus("从私钥提取公钥完成");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"从私钥提取公钥失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("从私钥提取公钥失败");
            }
        }

        private void btnConvert_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textInputKey.Text))
                {
                    MessageBox.Show("请先输入密钥内容！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在进行格式转换...");

                var inputKeyType = (RSAUtil.RSAKeyType)comboInputKeyType.SelectedIndex;
                var inputFormat = (RSAUtil.RSAKeyFormat)comboInputFormat.SelectedIndex;
                var outputKeyType = (RSAUtil.RSAKeyType)comboOutputKeyType.SelectedIndex;
                var outputFormat = (RSAUtil.RSAKeyFormat)comboOutputFormat.SelectedIndex;

                bool isPrivateKey = radioPrivateKey.Checked;

                string convertedKey = RSAUtil.ConvertKeyFormat(
                    textInputKey.Text, 
                    isPrivateKey, 
                    inputFormat, 
                    inputKeyType, 
                    outputFormat, 
                    outputKeyType);

                textOutputKey.Text = convertedKey;

                SetStatus($"格式转换完成 - {inputKeyType}/{inputFormat} -> {outputKeyType}/{outputFormat}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"格式转换失败：{ex.Message}\n\n请检查：\n1. 密钥内容是否正确\n2. 密钥类型选择是否匹配\n3. 输入格式选择是否正确", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("格式转换失败");
            }
        }

        private void btnClear_Click(object sender, EventArgs e)
        {
            textInputKey.Clear();
            textOutputKey.Clear();
            labelValidationResult.Text = "验证结果: 等待验证";
            labelValidationResult.ForeColor = Color.Gray;
            _publicKeyForValidation = string.Empty;
            _privateKeyForValidation = string.Empty;
            SetStatus("已清空所有内容");
        }

        private void btnSaveToFile_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textOutputKey.Text))
                {
                    MessageBox.Show("没有可保存的内容！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                using (SaveFileDialog saveFileDialog = new SaveFileDialog())
                {
                    var outputFormat = (RSAUtil.RSAKeyFormat)comboOutputFormat.SelectedIndex;
                    var keyType = radioPrivateKey.Checked ? "private" : "public";
                    
                    string extension = outputFormat switch
                    {
                        RSAUtil.RSAKeyFormat.PEM => ".pem",
                        RSAUtil.RSAKeyFormat.Base64 => ".txt",
                        RSAUtil.RSAKeyFormat.Hex => ".txt",
                        _ => ".txt"
                    };

                    saveFileDialog.Filter = GetFileFilter(outputFormat);
                    saveFileDialog.Title = "保存转换后的密钥";
                    saveFileDialog.FileName = $"rsa_{keyType}_key{extension}";

                    if (saveFileDialog.ShowDialog() == DialogResult.OK)
                    {
                        File.WriteAllText(saveFileDialog.FileName, textOutputKey.Text, Encoding.UTF8);
                        SetStatus("密钥文件保存成功");
                        MessageBox.Show("密钥文件保存成功！", "成功", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"保存文件失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("保存文件失败");
            }
        }

        private void btnCopyToClipboard_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textOutputKey.Text))
                {
                    MessageBox.Show("没有可复制的内容！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                Clipboard.SetText(textOutputKey.Text);
                SetStatus("已复制到剪贴板");
                MessageBox.Show("已复制到剪贴板！", "成功", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"复制到剪贴板失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("复制到剪贴板失败");
            }
        }

        private void textInputKey_TextChanged(object sender, EventArgs e)
        {
            // 当输入密钥内容改变时，自动检测密钥类型
            if (!string.IsNullOrEmpty(textInputKey.Text))
            {
                AutoDetectKeyType(textInputKey.Text);
            }
            else
            {
                // 清空验证结果
                labelValidationResult.Text = "验证结果: 等待验证";
                labelValidationResult.ForeColor = Color.Gray;
                _publicKeyForValidation = string.Empty;
                _privateKeyForValidation = string.Empty;
            }
        }

        #endregion

        #region 辅助方法

        private void AutoDetectKeyType(string keyContent)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(keyContent))
                    return;

                // 检测是否为私钥
                bool isPrivateKey = keyContent.Contains("PRIVATE KEY") || 
                                   keyContent.Contains("BEGIN RSA PRIVATE KEY") ||
                                   keyContent.Contains("<D>") || // XML格式私钥标识
                                   keyContent.Contains("\"d\":"); // JSON格式私钥标识

                if (isPrivateKey)
                {
                    radioPrivateKey.Checked = true;
                    
                    // 存储私钥用于验证
                    _privateKeyForValidation = keyContent;
                    _privateKeyFormatForValidation = DetectKeyFormat(keyContent);
                    _privateKeyTypeForValidation = DetectKeyType(keyContent);
                }
                else
                {
                    radioPublicKey.Checked = true;
                    
                    // 存储公钥用于验证
                    _publicKeyForValidation = keyContent;
                    _publicKeyFormatForValidation = DetectKeyFormat(keyContent);
                    _publicKeyTypeForValidation = DetectKeyType(keyContent);
                }

                // 更新输入格式选择
                var detectedFormat = DetectKeyFormat(keyContent);
                comboInputFormat.SelectedIndex = (int)detectedFormat;

                // 更新输入密钥类型选择
                var detectedType = DetectKeyType(keyContent);
                comboInputKeyType.SelectedIndex = (int)detectedType;
            }
            catch
            {
                // 自动检测失败时保持默认值
            }
        }

        private RSAUtil.RSAKeyFormat DetectKeyFormat(string keyContent)
        {
            if (keyContent.Contains("-----BEGIN") && keyContent.Contains("-----END"))
                return RSAUtil.RSAKeyFormat.PEM;
            
            // 检查是否为纯Base64（没有PEM头尾）
            if (IsBase64String(keyContent.Replace("\r", "").Replace("\n", "").Trim()))
                return RSAUtil.RSAKeyFormat.Base64;
            
            // 检查是否为Hex
            if (IsHexString(keyContent.Replace("\r", "").Replace("\n", "").Replace(" ", "").Replace("-", "")))
                return RSAUtil.RSAKeyFormat.Hex;

            return RSAUtil.RSAKeyFormat.PEM; // 默认
        }

        private RSAUtil.RSAKeyType DetectKeyType(string keyContent)
        {
            // PKCS#8 标识
            if (keyContent.Contains("BEGIN PRIVATE KEY") || keyContent.Contains("BEGIN PUBLIC KEY"))
                return RSAUtil.RSAKeyType.PKCS8;
            
            // PKCS#1 标识
            if (keyContent.Contains("BEGIN RSA PRIVATE KEY") || keyContent.Contains("BEGIN RSA PUBLIC KEY"))
                return RSAUtil.RSAKeyType.PKCS1;

            return RSAUtil.RSAKeyType.PKCS1; // 默认
        }

        private bool IsBase64String(string str)
        {
            if (string.IsNullOrWhiteSpace(str))
                return false;

            try
            {
                Convert.FromBase64String(str);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private bool IsHexString(string str)
        {
            if (string.IsNullOrWhiteSpace(str) || str.Length % 2 != 0)
                return false;

            return str.All(c => "0123456789ABCDEFabcdef".Contains(c));
        }

        private bool ValidateKeyPair(string publicKeyStr, string privateKeyStr,
            RSAUtil.RSAKeyFormat publicKeyFormat, RSAUtil.RSAKeyType publicKeyType,
            RSAUtil.RSAKeyFormat privateKeyFormat, RSAUtil.RSAKeyType privateKeyType)
        {
            try
            {
                // 解析公钥和私钥
                var publicKey = (RsaKeyParameters)RSAUtil.ParseKey(publicKeyStr, false, publicKeyFormat, publicKeyType);
                var privateKey = (RsaPrivateCrtKeyParameters)RSAUtil.ParseKey(privateKeyStr, true, privateKeyFormat, privateKeyType);

                // 检查模数是否一致
                if (!publicKey.Modulus.Equals(privateKey.Modulus))
                    return false;

                // 检查公指数是否一致
                if (!publicKey.Exponent.Equals(privateKey.PublicExponent))
                    return false;

                // 进行加解密测试验证
                string testMessage = "RSA Key Pair Validation Test";
                string encryptedMessage = RSAUtil.Encrypt(testMessage, publicKey);
                string decryptedMessage = RSAUtil.Decrypt(encryptedMessage, privateKey);

                return testMessage == decryptedMessage;
            }
            catch
            {
                return false;
            }
        }

        private string GetFileFilter(RSAUtil.RSAKeyFormat format)
        {
            return format switch
            {
                RSAUtil.RSAKeyFormat.PEM => "PEM文件 (*.pem)|*.pem|所有文件 (*.*)|*.*",
                RSAUtil.RSAKeyFormat.Base64 => "文本文件 (*.txt)|*.txt|所有文件 (*.*)|*.*",
                RSAUtil.RSAKeyFormat.Hex => "文本文件 (*.txt)|*.txt|所有文件 (*.*)|*.*",
                _ => "所有文件 (*.*)|*.*"
            };
        }

        #endregion
    }
}