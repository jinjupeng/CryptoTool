using CryptoTool.Common;
using CryptoTool.Common.GM;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using System.Collections.Generic;
using Newtonsoft.Json;

namespace CryptoTool.Win
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();

            // 设置窗口可调整大小
            this.WindowState = FormWindowState.Maximized;
            this.MinimumSize = new Size(1400, 800);
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            // 初始化默认值
            comboRSAKeySize.SelectedIndex = 1; // 2048
            comboRSAKeyFormat.SelectedIndex = 0; // XML
            comboRSAType.SelectedIndex = 1; // RSA2
            comboSM4Mode.SelectedIndex = 0; // ECB
            comboSM4Padding.SelectedIndex = 0; // PKCS7
            comboSM4KeyFormat.SelectedIndex = 0; // Base64
            comboSM4IVFormat.SelectedIndex = 0; // Base64
            comboSM4PlaintextFormat.SelectedIndex = 0; // Text
            comboSM4CiphertextFormat.SelectedIndex = 0; // Base64
            comboSM2KeyFormat.SelectedIndex = 0; // Base64
            comboSM2CipherFormat.SelectedIndex = 0; // C1C3C2
            comboSM2SignFormat.SelectedIndex = 0; // ASN1

            // 初始化医保默认值
            textMedicareAppId.Text = "43AF047BBA47FC8A1AE8EFB2XXXXXXXX";
            textMedicareAppSecret.Text = "4117E877F5FA0A0188891283E4B617D5";
            textMedicareEncType.Text = "SM4";
            textMedicareSignType.Text = "SM2";
            textMedicareVersion.Text = "2.0.1";

            // 设置默认的业务数据示例
            var defaultData = new
            {
                appId = "43AF047BBA47FC8A1AE8EFB2XXXXXXXX",
                appUserId = "o8z4C5avQXqC0aWFPf1Mzu6D7xxxx",
                idNo = "350582xxxxxxxx3519",
                idType = "01",
                phoneNumber = "137xxxxx033",
                userName = "测试"
            };
            textMedicareData.Text = JsonConvert.SerializeObject(defaultData, Formatting.Indented);

            // 设置当前时间戳
            textMedicareTimestamp.Text = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString();

            // 绑定事件
            this.btnGenerateMedicareKey.Click += new System.EventHandler(this.btnGenerateMedicareKey_Click);

            SetStatus("就绪");
        }

        #region RSA功能

        private void btnGenerateRSAKey_Click(object sender, EventArgs e)
        {
            try
            {
                SetStatus("正在生成RSA密钥对...");

                int keySize = int.Parse(comboRSAKeySize.SelectedItem.ToString());
                string formatText = comboRSAKeyFormat.SelectedIndex.ToString();
                RSAUtil.RSAKeyFormat format = (RSAUtil.RSAKeyFormat)Enum.Parse(typeof(RSAUtil.RSAKeyFormat), formatText);

                var keyPair = RSAUtil.CreateRSAKey(keySize, format);

                textRSAPublicKey.Text = keyPair.Key;
                textRSAPrivateKey.Text = keyPair.Value;

                SetStatus($"RSA密钥对生成完成 - {keySize}位 {formatText}格式");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"生成RSA密钥对失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("生成RSA密钥对失败");
            }
        }

        private void btnImportRSAKey_Click(object sender, EventArgs e)
        {
            try
            {
                using (OpenFileDialog openFileDialog = new OpenFileDialog())
                {
                    openFileDialog.Filter = "密钥文件 (*.txt;*.key;*.xml)|*.txt;*.key;*.xml|所有文件 (*.*)|*.*";
                    openFileDialog.Title = "导入RSA密钥文件";

                    if (openFileDialog.ShowDialog() == DialogResult.OK)
                    {
                        string content = File.ReadAllText(openFileDialog.FileName, Encoding.UTF8);

                        // 尝试解析文件内容
                        if (content.Contains("<RSAKeyValue>") || content.Contains("-----BEGIN"))
                        {
                            // 如果是XML格式或PEM格式，将公钥和私钥分别存储在一个文件中
                            // 或者按特定格式分割
                            string[] parts = content.Split(new string[] { "-----END", "</RSAKeyValue>" }, StringSplitOptions.RemoveEmptyEntries);

                            if (parts.Length >= 2)
                            {
                                textRSAPublicKey.Text = parts[0].Trim() + (content.Contains("-----END") ? "-----END PUBLIC KEY-----" : "</RSAKeyValue>");
                                textRSAPrivateKey.Text = parts[1].Trim();
                            }
                            else
                            {
                                // 如果只有一个密钥，判断是公钥还是私钥
                                if (content.Contains("PRIVATE") || content.Contains("<D>"))
                                {
                                    textRSAPrivateKey.Text = content.Trim();
                                }
                                else
                                {
                                    textRSAPublicKey.Text = content.Trim();
                                }
                            }
                        }
                        else
                        {
                            // 简单格式：每行一个密钥
                            string[] lines = content.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

                            if (lines.Length >= 2)
                            {
                                textRSAPublicKey.Text = lines[0].Trim();
                                textRSAPrivateKey.Text = lines[1].Trim();
                            }
                            else if (lines.Length == 1)
                            {
                                // 如果只有一行，先清空然后设置
                                textRSAPublicKey.Text = "";
                                textRSAPrivateKey.Text = "";
                                textRSAPublicKey.Text = lines[0].Trim();
                            }
                        }

                        SetStatus("RSA密钥导入成功");
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导入RSA密钥失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("导入RSA密钥失败");
            }
        }

        private void btnExportRSAKey_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textRSAPublicKey.Text) && string.IsNullOrEmpty(textRSAPrivateKey.Text))
                {
                    MessageBox.Show("请先生成或输入RSA密钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                using (SaveFileDialog saveFileDialog = new SaveFileDialog())
                {
                    saveFileDialog.Filter = "密钥文件 (*.txt)|*.txt|XML文件 (*.xml)|*.xml|所有文件 (*.*)|*.*";
                    saveFileDialog.Title = "导出RSA密钥文件";
                    saveFileDialog.FileName = "rsa_keys.txt";

                    if (saveFileDialog.ShowDialog() == DialogResult.OK)
                    {
                        StringBuilder content = new StringBuilder();

                        if (!string.IsNullOrEmpty(textRSAPublicKey.Text))
                        {
                            content.AppendLine("公钥：");
                            content.AppendLine(textRSAPublicKey.Text);
                            content.AppendLine();
                        }

                        if (!string.IsNullOrEmpty(textRSAPrivateKey.Text))
                        {
                            content.AppendLine("私钥：");
                            content.AppendLine(textRSAPrivateKey.Text);
                        }

                        File.WriteAllText(saveFileDialog.FileName, content.ToString(), Encoding.UTF8);
                        SetStatus("RSA密钥导出成功");
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导出RSA密钥失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("导出RSA密钥失败");
            }
        }

        private void btnRSAEncrypt_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textRSAPlainText.Text))
                {
                    MessageBox.Show("请输入明文！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textRSAPublicKey.Text))
                {
                    MessageBox.Show("请先生成或输入RSA公钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在进行RSA加密...");

                string formatText = comboRSAKeyFormat.SelectedItem.ToString();
                RSAUtil.RSAKeyFormat format = (RSAUtil.RSAKeyFormat)Enum.Parse(typeof(RSAUtil.RSAKeyFormat), formatText);

                string cipherText = RSAUtil.EncryptByRSA(textRSAPlainText.Text, textRSAPublicKey.Text, format);
                textRSACipherText.Text = cipherText;

                SetStatus("RSA加密完成");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"RSA加密失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("RSA加密失败");
            }
        }

        private void btnRSADecrypt_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textRSACipherText.Text))
                {
                    MessageBox.Show("请输入密文！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textRSAPrivateKey.Text))
                {
                    MessageBox.Show("请先生成或输入RSA私钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在进行RSA解密...");

                string formatText = comboRSAKeyFormat.SelectedItem.ToString();
                RSAUtil.RSAKeyFormat format = (RSAUtil.RSAKeyFormat)Enum.Parse(typeof(RSAUtil.RSAKeyFormat), formatText);

                string plainText = RSAUtil.DecryptByRSA(textRSACipherText.Text, textRSAPrivateKey.Text, format);
                textRSAPlainText.Text = plainText;

                SetStatus("RSA解密完成");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"RSA解密失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("RSA解密失败");
            }
        }

        private void btnRSASign_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textRSASignData.Text))
                {
                    MessageBox.Show("请输入要签名的原文数据！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textRSAPrivateKey.Text))
                {
                    MessageBox.Show("请先生成或输入RSA私钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在进行RSA签名...");

                string rsaTypeText = comboRSAType.SelectedItem.ToString();
                string formatText = comboRSAKeyFormat.SelectedItem.ToString();

                RSAUtil.RSAType rsaType = (RSAUtil.RSAType)Enum.Parse(typeof(RSAUtil.RSAType), rsaTypeText);
                RSAUtil.RSAKeyFormat format = (RSAUtil.RSAKeyFormat)Enum.Parse(typeof(RSAUtil.RSAKeyFormat), formatText);

                string signature = RSAUtil.HashAndSignString(textRSASignData.Text, textRSAPrivateKey.Text, rsaType, format);
                textRSASignature.Text = signature;

                SetStatus($"RSA签名完成 - 使用{rsaTypeText}算法");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"RSA签名失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("RSA签名失败");
            }
        }

        private void btnRSAVerify_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textRSASignData.Text))
                {
                    MessageBox.Show("请输入原文数据！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textRSASignature.Text))
                {
                    MessageBox.Show("请输入签名数据！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textRSAPublicKey.Text))
                {
                    MessageBox.Show("请先生成或输入RSA公钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在进行RSA验签...");

                string rsaTypeText = comboRSAType.SelectedItem.ToString();
                string formatText = comboRSAKeyFormat.SelectedItem.ToString();

                RSAUtil.RSAType rsaType = (RSAUtil.RSAType)Enum.Parse(typeof(RSAUtil.RSAType), rsaTypeText);
                RSAUtil.RSAKeyFormat format = (RSAUtil.RSAKeyFormat)Enum.Parse(typeof(RSAUtil.RSAKeyFormat), formatText);

                bool verifyResult = RSAUtil.VerifySigned(textRSASignData.Text, textRSASignature.Text, textRSAPublicKey.Text, rsaType, format);

                labelRSAVerifyResult.Text = $"验签结果: {(verifyResult ? "验证成功" : "验证失败")}";
                labelRSAVerifyResult.ForeColor = verifyResult ? Color.Green : Color.Red;

                SetStatus($"RSA验签完成 - {(verifyResult ? "验证成功" : "验证失败")}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"RSA验签失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                labelRSAVerifyResult.Text = "验签结果: 验证异常";
                labelRSAVerifyResult.ForeColor = Color.Red;
                SetStatus("RSA验签失败");
            }
        }

        #endregion

        #region SM4功能

        private void btnGenerateSM4Key_Click(object sender, EventArgs e)
        {
            try
            {
                SetStatus("正在生成SM4密钥...");

                string formatText = comboSM4KeyFormat.SelectedItem.ToString();
                SM4Util.FormatType format = (SM4Util.FormatType)Enum.Parse(typeof(SM4Util.FormatType), formatText);

                string key = SM4Util.GenerateKey(format);
                textSM4Key.Text = key;
                SetStatus($"SM4密钥生成完成 - {formatText}格式");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"生成SM4密钥失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("生成SM4密钥失败");
            }
        }

        private void btnGenerateSM4IV_Click(object sender, EventArgs e)
        {
            try
            {
                SetStatus("正在生成SM4初始向量...");

                string formatText = comboSM4IVFormat.SelectedItem.ToString();
                SM4Util.FormatType format = (SM4Util.FormatType)Enum.Parse(typeof(SM4Util.FormatType), formatText);

                string iv = SM4Util.GenerateIV(format);
                textSM4IV.Text = iv;
                SetStatus($"SM4初始向量生成完成 - {formatText}格式");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"生成SM4初始向量失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("生成SM4初始向量失败");
            }
        }

        private void btnImportSM4Key_Click(object sender, EventArgs e)
        {
            try
            {
                using (OpenFileDialog openFileDialog = new OpenFileDialog())
                {
                    openFileDialog.Filter = "密钥文件 (*.txt;*.key)|*.txt;*.key|所有文件 (*.*)|*.*";
                    openFileDialog.Title = "导入SM4密钥文件";

                    if (openFileDialog.ShowDialog() == DialogResult.OK)
                    {
                        string content = File.ReadAllText(openFileDialog.FileName, Encoding.UTF8);
                        string[] lines = content.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

                        if (lines.Length >= 2)
                        {
                            textSM4Key.Text = lines[0].Trim();
                            textSM4IV.Text = lines[1].Trim();
                            SetStatus("SM4密钥导入成功");
                        }
                        else if (lines.Length == 1)
                        {
                            textSM4Key.Text = lines[0].Trim();
                            SetStatus("SM4密钥导入成功");
                        }
                        else
                        {
                            MessageBox.Show("密钥文件格式错误！", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导入SM4密钥失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("导入SM4密钥失败");
            }
        }

        private void btnExportSM4Key_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textSM4Key.Text))
                {
                    MessageBox.Show("请先生成或输入SM4密钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                using (SaveFileDialog saveFileDialog = new SaveFileDialog())
                {
                    saveFileDialog.Filter = "密钥文件 (*.txt)|*.txt|所有文件 (*.*)|*.*";
                    saveFileDialog.Title = "导出SM4密钥文件";
                    saveFileDialog.FileName = "sm4_keys.txt";

                    if (saveFileDialog.ShowDialog() == DialogResult.OK)
                    {
                        StringBuilder content = new StringBuilder();
                        content.AppendLine($"SM4密钥：");
                        content.AppendLine(textSM4Key.Text);

                        if (!string.IsNullOrEmpty(textSM4IV.Text))
                        {
                            content.AppendLine();
                            content.AppendLine($"初始向量：");
                            content.AppendLine(textSM4IV.Text);
                        }

                        File.WriteAllText(saveFileDialog.FileName, content.ToString(), Encoding.UTF8);
                        SetStatus("SM4密钥导出成功");
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导出SM4密钥失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("导出SM4密钥失败");
            }
        }

        private void btnSM4Encrypt_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textSM4PlainText.Text))
                {
                    MessageBox.Show("请输入明文！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textSM4Key.Text))
                {
                    MessageBox.Show("请先生成或输入SM4密钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                string mode = comboSM4Mode.SelectedItem.ToString();
                if (mode == "CBC" && string.IsNullOrEmpty(textSM4IV.Text))
                {
                    MessageBox.Show("CBC模式需要初始向量，请先生成或输入初始向量！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在进行SM4加密...");

                string paddingText = comboSM4Padding.SelectedItem.ToString();
                string keyFormatText = comboSM4KeyFormat.SelectedItem.ToString();
                string plaintextFormatText = comboSM4PlaintextFormat.SelectedItem.ToString();
                string ciphertextFormatText = comboSM4CiphertextFormat.SelectedItem.ToString();

                SM4Util.PaddingMode padding = (SM4Util.PaddingMode)Enum.Parse(typeof(SM4Util.PaddingMode), paddingText);
                SM4Util.FormatType keyFormat = (SM4Util.FormatType)Enum.Parse(typeof(SM4Util.FormatType), keyFormatText);
                SM4Util.FormatType plaintextFormat = (SM4Util.FormatType)Enum.Parse(typeof(SM4Util.FormatType), plaintextFormatText);
                SM4Util.FormatType ciphertextFormat = (SM4Util.FormatType)Enum.Parse(typeof(SM4Util.FormatType), ciphertextFormatText);

                string cipherText;
                if (mode == "ECB")
                {
                    cipherText = SM4Util.EncryptEcbWithFormat(textSM4PlainText.Text, textSM4Key.Text, keyFormat, plaintextFormat, ciphertextFormat, padding);
                }
                else // CBC
                {
                    string ivFormatText = comboSM4IVFormat.SelectedItem.ToString();
                    SM4Util.FormatType ivFormat = (SM4Util.FormatType)Enum.Parse(typeof(SM4Util.FormatType), ivFormatText);
                    cipherText = SM4Util.EncryptCbcWithFormat(textSM4PlainText.Text, textSM4Key.Text, textSM4IV.Text, keyFormat, ivFormat, plaintextFormat, ciphertextFormat, padding);
                }

                textSM4CipherText.Text = cipherText;
                SetStatus($"SM4加密完成 - 使用{mode}模式，明文{plaintextFormatText}格式，输出{ciphertextFormatText}格式");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"SM4加密失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("SM4加密失败");
            }
        }

        private void btnSM4Decrypt_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textSM4CipherText.Text))
                {
                    MessageBox.Show("请输入密文！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textSM4Key.Text))
                {
                    MessageBox.Show("请先生成或输入SM4密钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                string mode = comboSM4Mode.SelectedItem.ToString();
                if (mode == "CBC" && string.IsNullOrEmpty(textSM4IV.Text))
                {
                    MessageBox.Show("CBC模式需要初始向量，请先生成或输入初始向量！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在进行SM4解密...");

                string paddingText = comboSM4Padding.SelectedItem.ToString();
                string keyFormatText = comboSM4KeyFormat.SelectedItem.ToString();
                string plaintextFormatText = comboSM4PlaintextFormat.SelectedItem.ToString();
                string ciphertextFormatText = comboSM4CiphertextFormat.SelectedItem.ToString();

                SM4Util.PaddingMode padding = (SM4Util.PaddingMode)Enum.Parse(typeof(SM4Util.PaddingMode), paddingText);
                SM4Util.FormatType keyFormat = (SM4Util.FormatType)Enum.Parse(typeof(SM4Util.FormatType), keyFormatText);
                SM4Util.FormatType plaintextFormat = (SM4Util.FormatType)Enum.Parse(typeof(SM4Util.FormatType), plaintextFormatText);
                SM4Util.FormatType ciphertextFormat = (SM4Util.FormatType)Enum.Parse(typeof(SM4Util.FormatType), ciphertextFormatText);

                string plainText;
                if (mode == "ECB")
                {
                    plainText = SM4Util.DecryptEcbWithFormat(textSM4CipherText.Text, textSM4Key.Text, keyFormat, ciphertextFormat, plaintextFormat, padding);
                }
                else // CBC
                {
                    string ivFormatText = comboSM4IVFormat.SelectedItem.ToString();
                    SM4Util.FormatType ivFormat = (SM4Util.FormatType)Enum.Parse(typeof(SM4Util.FormatType), ivFormatText);
                    plainText = SM4Util.DecryptCbcWithFormat(textSM4CipherText.Text, textSM4Key.Text, textSM4IV.Text, keyFormat, ivFormat, ciphertextFormat, plaintextFormat, padding);
                }

                textSM4PlainText.Text = plainText;
                SetStatus($"SM4解密完成 - 使用{mode}模式，密文{ciphertextFormatText}格式，输出{plaintextFormatText}格式");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"SM4解密失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("SM4解密失败");
            }
        }

        private void comboSM4Mode_SelectedIndexChanged(object sender, EventArgs e)
        {
            // 当选择ECB模式时，禁用初始向量相关控件
            bool isCBC = comboSM4Mode.SelectedItem.ToString() == "CBC";
            textSM4IV.Enabled = isCBC;
            btnGenerateSM4IV.Enabled = isCBC;
            comboSM4IVFormat.Enabled = isCBC;

            if (!isCBC)
            {
                textSM4IV.Text = "";
            }
        }

        private void comboSM4KeyFormat_SelectedIndexChanged(object sender, EventArgs e)
        {
            // 当格式变化时，如果当前有密钥内容，尝试转换格式
            if (string.IsNullOrEmpty(textSM4Key.Text)) return;

            try
            {
                // 暂不实现自动格式转换，避免错误转换
                // 用户需要重新生成密钥或手动输入正确格式的密钥
            }
            catch
            {
                // 格式转换失败，忽略
            }
        }

        private void comboSM4IVFormat_SelectedIndexChanged(object sender, EventArgs e)
        {
            // 当格式变化时，如果当前有IV内容，尝试转换格式
            if (string.IsNullOrEmpty(textSM4IV.Text)) return;

            try
            {
                // 暂不实现自动格式转换，避免错误转换
                // 用户需要重新生成IV或手动输入正确格式的IV
            }
            catch
            {
                // 格式转换失败，忽略
            }
        }

        #endregion

        #region SM2功能

        private void btnGenerateSM2Key_Click(object sender, EventArgs e)
        {
            try
            {
                SetStatus("正在生成SM2密钥对...");

                var keyPair = SM2Util.GenerateKeyPair();
                var publicKey = (ECPublicKeyParameters)keyPair.Public;
                var privateKey = (ECPrivateKeyParameters)keyPair.Private;

                string formatText = comboSM2KeyFormat.SelectedItem.ToString();

                if (formatText == "Base64")
                {
                    textSM2PublicKey.Text = SM2Util.PublicKeyToRawBase64(publicKey);
                    textSM2PrivateKey.Text = SM2Util.PrivateKeyToRawBase64(privateKey);
                }
                else // Hex
                {
                    textSM2PublicKey.Text = SM2Util.PublicKeyToHex(publicKey);
                    textSM2PrivateKey.Text = SM2Util.PrivateKeyToHex(privateKey);
                }

                SetStatus($"SM2密钥对生成完成 - {formatText}格式");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"生成SM2密钥对失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("生成SM2密钥对失败");
            }
        }

        private void btnImportSM2Key_Click(object sender, EventArgs e)
        {
            try
            {
                using (OpenFileDialog openFileDialog = new OpenFileDialog())
                {
                    openFileDialog.Filter = "密钥文件 (*.txt;*.key)|*.txt;*.key|所有文件 (*.*)|*.*";
                    openFileDialog.Title = "导入SM2密钥文件";

                    if (openFileDialog.ShowDialog() == DialogResult.OK)
                    {
                        string content = File.ReadAllText(openFileDialog.FileName, Encoding.UTF8);
                        string[] lines = content.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

                        if (lines.Length >= 2)
                        {
                            textSM2PublicKey.Text = lines[0].Trim();
                            textSM2PrivateKey.Text = lines[1].Trim();
                            SetStatus("SM2密钥导入成功");
                        }
                        else
                        {
                            MessageBox.Show("密钥文件格式错误！应包含公钥和私钥两行。", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导入SM2密钥失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("导入SM2密钥失败");
            }
        }

        private void btnExportSM2Key_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textSM2PublicKey.Text) || string.IsNullOrEmpty(textSM2PrivateKey.Text))
                {
                    MessageBox.Show("请先生成或输入SM2密钥对！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                using (SaveFileDialog saveFileDialog = new SaveFileDialog())
                {
                    saveFileDialog.Filter = "密钥文件 (*.txt)|*.txt|所有文件 (*.*)|*.*";
                    saveFileDialog.Title = "导出SM2密钥文件";
                    saveFileDialog.FileName = "sm2_keys.txt";

                    if (saveFileDialog.ShowDialog() == DialogResult.OK)
                    {
                        string content = $"公钥：\r\n{textSM2PublicKey.Text}\r\n\r\n私钥：\r\n{textSM2PrivateKey.Text}";
                        File.WriteAllText(saveFileDialog.FileName, content, Encoding.UTF8);
                        SetStatus("SM2密钥导出成功");
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导出SM2密钥失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("导出SM2密钥失败");
            }
        }

        private void btnSM2Encrypt_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textSM2PlainText.Text))
                {
                    MessageBox.Show("请输入明文！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textSM2PublicKey.Text))
                {
                    MessageBox.Show("请先生成或输入SM2公钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在进行SM2加密...");

                string formatText = comboSM2KeyFormat.SelectedItem.ToString();
                string cipherFormatText = comboSM2CipherFormat.SelectedItem.ToString();

                SM2Util.SM2CipherFormat cipherFormat = (SM2Util.SM2CipherFormat)Enum.Parse(typeof(SM2Util.SM2CipherFormat), cipherFormatText);

                string cipherText;
                if (formatText == "Base64")
                {
                    cipherText = SM2Util.Encrypt(textSM2PlainText.Text, textSM2PublicKey.Text, Encoding.UTF8, cipherFormat);
                }
                else // Hex
                {
                    var publicKey = SM2Util.ParsePublicKeyFromHex(textSM2PublicKey.Text);
                    cipherText = SM2Util.Encrypt(textSM2PlainText.Text, publicKey, Encoding.UTF8, cipherFormat);
                }

                textSM2CipherText.Text = cipherText;
                SetStatus($"SM2加密完成 - 使用{cipherFormatText}格式");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"SM2加密失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("SM2加密失败");
            }
        }

        private void btnSM2Decrypt_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textSM2CipherText.Text))
                {
                    MessageBox.Show("请输入密文！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textSM2PrivateKey.Text))
                {
                    MessageBox.Show("请先生成或输入SM2私钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在进行SM2解密...");

                string formatText = comboSM2KeyFormat.SelectedItem.ToString();
                string cipherFormatText = comboSM2CipherFormat.SelectedItem.ToString();

                SM2Util.SM2CipherFormat cipherFormat = (SM2Util.SM2CipherFormat)Enum.Parse(typeof(SM2Util.SM2CipherFormat), cipherFormatText);

                string plainText;
                if (formatText == "Base64")
                {
                    plainText = SM2Util.DecryptToString(textSM2CipherText.Text, textSM2PrivateKey.Text, Encoding.UTF8, cipherFormat);
                }
                else // Hex
                {
                    var privateKey = SM2Util.ParsePrivateKeyFromHex(textSM2PrivateKey.Text);
                    plainText = SM2Util.DecryptToString(textSM2CipherText.Text, privateKey, Encoding.UTF8, cipherFormat);
                }

                textSM2PlainText.Text = plainText;
                SetStatus($"SM2解密完成 - 使用{cipherFormatText}格式");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"SM2解密失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("SM2解密失败");
            }
        }

        private void btnSM2Sign_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textSM2SignData.Text))
                {
                    MessageBox.Show("请输入要签名的原文数据！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textSM2PrivateKey.Text))
                {
                    MessageBox.Show("请先生成或输入SM2私钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在进行SM2签名...");

                string formatText = comboSM2KeyFormat.SelectedItem.ToString();
                string signFormatText = comboSM2SignFormat.SelectedItem.ToString();

                SM2Util.SM2SignatureFormat signFormat = (SM2Util.SM2SignatureFormat)Enum.Parse(typeof(SM2Util.SM2SignatureFormat), signFormatText);

                string signature;
                if (formatText == "Base64")
                {
                    signature = SM2Util.SignSm3WithSm2(textSM2SignData.Text, textSM2PrivateKey.Text, Encoding.UTF8, signFormat);
                }
                else // Hex
                {
                    var privateKey = SM2Util.ParsePrivateKeyFromHex(textSM2PrivateKey.Text);
                    signature = SM2Util.SignSm3WithSm2(textSM2SignData.Text, privateKey, Encoding.UTF8, signFormat);
                }

                textSM2Signature.Text = signature;
                SetStatus($"SM2签名完成 - 使用{signFormatText}格式");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"SM2签名失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("SM2签名失败");
            }
        }

        private void btnSM2Verify_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textSM2SignData.Text))
                {
                    MessageBox.Show("请输入原文数据！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textSM2Signature.Text))
                {
                    MessageBox.Show("请输入签名数据！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textSM2PublicKey.Text))
                {
                    MessageBox.Show("请先生成或输入SM2公钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在进行SM2验签...");

                string formatText = comboSM2KeyFormat.SelectedItem.ToString();
                string signFormatText = comboSM2SignFormat.SelectedItem.ToString();

                SM2Util.SM2SignatureFormat signFormat = (SM2Util.SM2SignatureFormat)Enum.Parse(typeof(SM2Util.SM2SignatureFormat), signFormatText);

                bool verifyResult;
                if (formatText == "Base64")
                {
                    verifyResult = SM2Util.VerifySm3WithSm2(textSM2SignData.Text, textSM2Signature.Text, textSM2PublicKey.Text, Encoding.UTF8, signFormat);
                }
                else // Hex
                {
                    var publicKey = SM2Util.ParsePublicKeyFromHex(textSM2PublicKey.Text);
                    verifyResult = SM2Util.VerifySm3WithSm2(textSM2SignData.Text, textSM2Signature.Text, publicKey, Encoding.UTF8, signFormat);
                }

                labelSM2VerifyResult.Text = $"验签结果: {(verifyResult ? "验证成功" : "验证失败")}";
                labelSM2VerifyResult.ForeColor = verifyResult ? Color.Green : Color.Red;

                SetStatus($"SM2验签完成 - {(verifyResult ? "验证成功" : "验证失败")}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"SM2验签失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                labelSM2VerifyResult.Text = "验签结果: 验证异常";
                labelSM2VerifyResult.ForeColor = Color.Red;
                SetStatus("SM2验签失败");
            }
        }

        #endregion

        #region 医保功能

        private void btnGenerateMedicareKey_Click(object sender, EventArgs e)
        {
            try
            {
                SetStatus("正在生成医保SM2密钥对...");

                var keyPair = SM2Util.GenerateKeyPair();
                var publicKey = (ECPublicKeyParameters)keyPair.Public;
                var privateKey = (ECPrivateKeyParameters)keyPair.Private;

                textMedicarePublicKey.Text = SM2Util.PublicKeyToHex(publicKey);
                textMedicarePrivateKey.Text = SM2Util.PrivateKeyToHex(privateKey);

                SetStatus("医保SM2密钥对生成完成");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"生成医保SM2密钥对失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("生成医保SM2密钥对失败");
            }
        }

        private void btnImportMedicareKey_Click(object sender, EventArgs e)
        {
            try
            {
                using (OpenFileDialog openFileDialog = new OpenFileDialog())
                {
                    openFileDialog.Filter = "密钥文件 (*.txt;*.key)|*.txt;*.key|所有文件 (*.*)|*.*";
                    openFileDialog.Title = "导入医保密钥文件";

                    if (openFileDialog.ShowDialog() == DialogResult.OK)
                    {
                        string content = File.ReadAllText(openFileDialog.FileName, Encoding.UTF8);
                        string[] lines = content.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

                        if (lines.Length >= 2)
                        {
                            textMedicarePublicKey.Text = lines[0].Trim();
                            textMedicarePrivateKey.Text = lines[1].Trim();
                            SetStatus("医保密钥导入成功");
                        }
                        else
                        {
                            MessageBox.Show("密钥文件格式错误！应包含公钥和私钥两行。", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导入医保密钥失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("导入医保密钥失败");
            }
        }

        private void btnExportMedicareKey_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textMedicarePublicKey.Text) || string.IsNullOrEmpty(textMedicarePrivateKey.Text))
                {
                    MessageBox.Show("请先生成或输入医保密钥对！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                using (SaveFileDialog saveFileDialog = new SaveFileDialog())
                {
                    saveFileDialog.Filter = "密钥文件 (*.txt)|*.txt|所有文件 (*.*)|*.*";
                    saveFileDialog.Title = "导出医保密钥文件";
                    saveFileDialog.FileName = "medicare_keys.txt";

                    if (saveFileDialog.ShowDialog() == DialogResult.OK)
                    {
                        string content = $"公钥：\r\n{textMedicarePublicKey.Text}\r\n\r\n私钥：\r\n{textMedicarePrivateKey.Text}";
                        File.WriteAllText(saveFileDialog.FileName, content, Encoding.UTF8);
                        SetStatus("医保密钥导出成功");
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导出医保密钥失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("导出医保密钥失败");
            }
        }

        private void btnMedicareSign_Click(object sender, EventArgs e)
        {
            try
            {
                if (ValidateMedicareInputs(false))
                {
                    SetStatus("正在进行医保签名...");

                    // 构造请求参数
                    var parameters = BuildMedicareParameters();

                    // 解析私钥
                    var privateKey = SM2Util.ParsePrivateKeyFromHex(textMedicarePrivateKey.Text);
                    string appSecret = textMedicareAppSecret.Text.Trim();

                    // 构造签名字符串
                    string signatureString = MedicareUtil.BuildSignatureBaseString(parameters, appSecret);
                    textMedicareSignatureString.Text = signatureString;

                    // 生成签名
                    string signData = MedicareUtil.SignParameters(parameters, privateKey, appSecret);
                    textMedicareSignData.Text = signData;

                    SetStatus("医保签名完成");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"医保签名失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("医保签名失败");
            }
        }

        private void btnMedicareVerify_Click(object sender, EventArgs e)
        {
            try
            {
                if (ValidateMedicareInputs(true))
                {
                    SetStatus("正在进行医保验签...");

                    // 构造参数（不包含signData进行验签）
                    var parameters = BuildMedicareParameters();

                    // 解析公钥
                    var publicKey = SM2Util.ParsePublicKeyFromHex(textMedicarePublicKey.Text);
                    string appSecret = textMedicareAppSecret.Text.Trim();
                    string signData = textMedicareSignData.Text.Trim();

                    // 验签
                    bool verifyResult = MedicareUtil.VerifyParametersSignature(parameters, signData, publicKey, appSecret);

                    MessageBox.Show($"验签结果：{(verifyResult ? "验证成功" : "验证失败")}",
                        "验签结果", MessageBoxButtons.OK,
                        verifyResult ? MessageBoxIcon.Information : MessageBoxIcon.Warning);

                    SetStatus($"医保验签完成 - {(verifyResult ? "验证成功" : "验证失败")}");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"医保验签失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("医保验签失败");
            }
        }

        private void btnMedicareEncrypt_Click(object sender, EventArgs e)
        {
            try
            {
                if (ValidateMedicareEncryptedInputs(false))
                {
                    SetStatus("正在进行医保数据加密...");

                    string appId = textMedicareAppId.Text.Trim();
                    string appSecret = textMedicareAppSecret.Text.Trim();

                    // 解析JSON数据
                    object dataObject;
                    try
                    {
                        dataObject = JsonConvert.DeserializeObject(textMedicareData.Text);
                    }
                    catch (JsonException)
                    {
                        // 如果不是有效JSON，使用原始字符串
                        dataObject = textMedicareData.Text;
                    }

                    // 加密数据
                    string encData = MedicareUtil.EncryptData(dataObject, appId, appSecret);
                    textMedicareEncData.Text = encData;

                    SetStatus("医保数据加密完成");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"医保数据加密失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("医保数据加密失败");
            }
        }

        private void btnMedicareDecrypt_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(textMedicareEncData.Text))
                {
                    MessageBox.Show("请输入要解密的encData！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrWhiteSpace(textMedicareAppId.Text) || string.IsNullOrWhiteSpace(textMedicareAppSecret.Text))
                {
                    MessageBox.Show("请输入AppId和AppSecret！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在进行医保数据解密...");

                string appId = textMedicareAppId.Text.Trim();
                string appSecret = textMedicareAppSecret.Text.Trim();
                string encData = textMedicareEncData.Text.Trim();

                // 解密数据
                string decryptedData = MedicareUtil.DecryptEncData(encData, appId, appSecret);

                // 尝试格式化JSON显示
                try
                {
                    var jsonObject = JsonConvert.DeserializeObject(decryptedData);
                    textMedicareDecData.Text = JsonConvert.SerializeObject(jsonObject, Formatting.Indented);
                }
                catch
                {
                    // 如果不是有效JSON，直接显示原始数据
                    textMedicareDecData.Text = decryptedData;
                }

                SetStatus("医保数据解密完成");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"医保数据解密失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("医保数据解密失败");
            }
        }

        /// <summary>
        /// 医保加密功能输入校验
        /// </summary>
        /// <param name="includeSignData"></param>
        /// <returns></returns>
        private bool ValidateMedicareEncryptedInputs(bool includeSignData)
        {
            if (string.IsNullOrWhiteSpace(textMedicareAppId.Text))
            {
                MessageBox.Show("请输入AppId！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }

            if (string.IsNullOrWhiteSpace(textMedicareAppSecret.Text))
            {
                MessageBox.Show("请输入AppSecret！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }

            if (string.IsNullOrWhiteSpace(textMedicareData.Text))
            {
                MessageBox.Show("请输入业务数据！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }

            return true;
        }

        /// <summary>
        /// 医保签名验签功能输入校验
        /// </summary>
        /// <param name="includeSignData"></param>
        /// <returns></returns>
        private bool ValidateMedicareInputs(bool includeSignData)
        {
            if (string.IsNullOrWhiteSpace(textMedicareAppId.Text))
            {
                MessageBox.Show("请输入AppId！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }

            if (string.IsNullOrWhiteSpace(textMedicareAppSecret.Text))
            {
                MessageBox.Show("请输入AppSecret！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }

            if (string.IsNullOrWhiteSpace(textMedicareTimestamp.Text))
            {
                MessageBox.Show("请输入时间戳！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }

            if (string.IsNullOrWhiteSpace(textMedicarePublicKey.Text))
            {
                MessageBox.Show("请先生成或输入公钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }

            if (string.IsNullOrWhiteSpace(textMedicarePrivateKey.Text))
            {
                MessageBox.Show("请先生成或输入私钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }

            if (includeSignData && string.IsNullOrWhiteSpace(textMedicareSignData.Text))
            {
                MessageBox.Show("请先进行签名操作获取SignData！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }

            return true;
        }

        private Dictionary<string, object> BuildMedicareParameters()
        {
            var parameters = new Dictionary<string, object>();

            parameters["appId"] = textMedicareAppId.Text.Trim();
            parameters["encType"] = textMedicareEncType.Text.Trim();
            parameters["signType"] = textMedicareSignType.Text.Trim();
            parameters["timestamp"] = textMedicareTimestamp.Text.Trim();
            parameters["version"] = textMedicareVersion.Text.Trim();

            // 如果有数据内容，添加data字段
            if (!string.IsNullOrWhiteSpace(textMedicareData.Text))
            {
                try
                {
                    // 尝试解析为JSON对象
                    var dataObject = JsonConvert.DeserializeObject(textMedicareData.Text);
                    parameters["data"] = dataObject;
                }
                catch (JsonException)
                {
                    // 如果不是有效JSON，使用原始字符串
                    parameters["data"] = textMedicareData.Text.Trim();
                }
            }

            return parameters;
        }

        #endregion

        #region 新增医保SM4密钥生成功能

        private void btnGenerateMedicareSM4Key_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(textMedicareAppId.Text))
                {
                    MessageBox.Show("请输入医保AppId！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrWhiteSpace(textMedicareAppSecret.Text))
                {
                    MessageBox.Show("请输入医保AppSecret！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                string appId = textMedicareAppId.Text.Trim();
                string appSecret = textMedicareAppSecret.Text.Trim();

                if (appId.Length < 16)
                {
                    MessageBox.Show("AppId长度不足16字节，无法派生SM4密钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在根据医保AppId和AppSecret生成SM4密钥...");

                // 使用MedicareUtil中的逻辑生成SM4密钥
                string derivedKey = GetMedicareSM4Key(appId, appSecret);
                textMedicareSM4Key.Text = derivedKey;

                // 同时更新SM4 Tab中的密钥，方便直接使用
                textSM4Key.Text = derivedKey;
                comboSM4KeyFormat.SelectedItem = "Hex";

                SetStatus($"医保SM4密钥生成完成 - 基于AppId和AppSecret派生");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"生成医保SM4密钥失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("生成医保SM4密钥失败");
            }
        }

        /// <summary>
        /// 根据医保规范，从AppId和AppSecret派生SM4密钥
        /// </summary>
        /// <param name="appId"></param>
        /// <param name="appSecret"></param>
        /// <returns></returns>
        private string GetMedicareSM4Key(string appId, string appSecret)
        {
            // 实现医保规范的SM4密钥派生算法
            // 以appId(渠道id)作为Key，对appSecret加密，得到新秘钥串，取前16字节作为SM4密钥

            if (appId.Length < 16)
            {
                throw new ArgumentException("appId长度不足16字节，无法派生SM4密钥", nameof(appId));
            }

            // 取appId的前16字节作为SM4密钥来加密appSecret
            string keyString = appId.Substring(0, 16);

            // 使用SM4-ECB模式，appId前16字符作为密钥，对appSecret进行加密
            string encryptedData = SM4Util.EncryptEcb(appSecret, keyString, Encoding.UTF8);

            // 将Base64结果转换为字节数组，再转换为Hex字符串，取前16个字符（8字节）作为最终的SM4密钥
            byte[] encryptedBytes = Convert.FromBase64String(encryptedData);
            string hexResult = SM4Util.BytesToHex(encryptedBytes);

            // 取前16个字符作为最终的SM4密钥（Hex格式，实际对应8字节）
            // 但SM4需要16字节密钥，所以取前32个字符（对应16字节）
            string finalKey = hexResult.Substring(0, Math.Min(32, hexResult.Length));

            return finalKey;
        }

        #endregion

        #region 辅助方法

        private void SetStatus(string message)
        {
            toolStripStatusLabel1.Text = message;
            Application.DoEvents();
        }

        #endregion

        private void textSM4Key_TextChanged(object sender, EventArgs e)
        {

        }

        /// <summary>
        /// 当时间戳文本框失去焦点且未填充内容时，自动更新为当前时间戳
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void TextMedicareTimestamp_Leave(object sender, EventArgs e)
        {
            if (string.IsNullOrWhiteSpace(textMedicareTimestamp.Text))
            {
                long timeStamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                textMedicareTimestamp.Text = timeStamp.ToString();
            }
        }
    }
}
