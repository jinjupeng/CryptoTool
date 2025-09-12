using CryptoTool.Common.Providers.GM;
using CryptoTool.Common.Enums;
using CryptoTool.Common.Utils;
using Org.BouncyCastle.Crypto.Parameters;
using System.Text;

namespace CryptoTool.Win
{
    public partial class SM2TabControl : UserControl
    {
        public event Action<string> StatusChanged;

        public SM2TabControl()
        {
            InitializeComponent();
            InitializeDefaults();
        }

        private void InitializeDefaults()
        {
            comboSM2KeyFormat.SelectedIndex = 0; // Base64
            comboSM2CipherFormat.SelectedIndex = 0; // C1C3C2
            comboSM2SignFormat.SelectedIndex = 0; // ASN1
        }

        private void SetStatus(string message)
        {
            StatusChanged?.Invoke(message);
        }

        #region SM2功能

        private void btnGenerateSM2Key_Click(object sender, EventArgs e)
        {
            try
            {
                SetStatus("正在生成SM2密钥对...");

                var keyPair = SM2Provider.GenerateKeyPair();
                var publicKey = (ECPublicKeyParameters)keyPair.Public;
                var privateKey = (ECPrivateKeyParameters)keyPair.Private;

                string? formatText = comboSM2KeyFormat.SelectedItem?.ToString();

                if (formatText == "Base64")
                {
                    textSM2PublicKey.Text = SM2Provider.PublicKeyToRawBase64(publicKey);
                    textSM2PrivateKey.Text = SM2Provider.PrivateKeyToRawBase64(privateKey);
                }
                else // Hex
                {
                    textSM2PublicKey.Text = SM2Provider.PublicKeyToHex(publicKey);
                    textSM2PrivateKey.Text = SM2Provider.PrivateKeyToHex(privateKey);
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

                string formatText = comboSM2KeyFormat.SelectedItem?.ToString() ?? "";
                string cipherFormatText = comboSM2CipherFormat.SelectedItem?.ToString() ?? "";

                SM2Provider.SM2CipherFormat cipherFormat = (SM2Provider.SM2CipherFormat)Enum.Parse(typeof(SM2Provider.SM2CipherFormat), cipherFormatText);

                string cipherText;
                if (formatText == "Base64")
                {
                    var sm2Provider = new SM2Provider();
                    cipherText = sm2Provider.Encrypt(textSM2PlainText.Text, textSM2PublicKey.Text, OutputFormat.Base64);
                }
                else // Hex
                {
                    var publicKey = SM2Provider.ParsePublicKeyFromHex(textSM2PublicKey.Text);
                    var dataBytes = Encoding.UTF8.GetBytes(textSM2PlainText.Text);
                    var cipherBytes = SM2Provider.Encrypt(dataBytes, publicKey, cipherFormat);
                    cipherText = CryptoCommonUtil.BytesToString(cipherBytes, OutputFormat.Base64);
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

                string formatText = comboSM2KeyFormat.SelectedItem?.ToString() ?? "";
                string cipherFormatText = comboSM2CipherFormat.SelectedItem?.ToString() ?? "";

                SM2Provider.SM2CipherFormat cipherFormat = (SM2Provider.SM2CipherFormat)Enum.Parse(typeof(SM2Provider.SM2CipherFormat), cipherFormatText);

                string plainText;
                if (formatText == "Base64")
                {
                    var sm2Provider = new SM2Provider();
                    plainText = sm2Provider.Decrypt(textSM2CipherText.Text, textSM2PrivateKey.Text, InputFormat.Base64);
                }
                else // Hex
                {
                    var privateKey = SM2Provider.ParsePrivateKeyFromHex(textSM2PrivateKey.Text);
                    var cipherBytes = CryptoCommonUtil.StringToBytes(textSM2CipherText.Text, InputFormat.Base64);
                    var plainBytes = SM2Provider.Decrypt(cipherBytes, privateKey, cipherFormat);
                    plainText = Encoding.UTF8.GetString(plainBytes);
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

                string formatText = comboSM2KeyFormat.SelectedItem?.ToString() ?? "";
                string signFormatText = comboSM2SignFormat.SelectedItem?.ToString() ?? "";

                SM2Provider.SM2SignatureFormat signFormat = (SM2Provider.SM2SignatureFormat)Enum.Parse(typeof(SM2Provider.SM2SignatureFormat), signFormatText);

                string signature;
                if (formatText == "Base64")
                {
                    // 使用接口方法进行签名
                    var sm2Provider = new SM2Provider();
                    signature = sm2Provider.Sign(textSM2SignData.Text, textSM2PrivateKey.Text, SignatureAlgorithm.SM3withSM2, OutputFormat.Base64);
                }
                else // Hex
                {
                    var privateKey = SM2Provider.ParsePrivateKeyFromHex(textSM2PrivateKey.Text);
                    var dataBytes = Encoding.UTF8.GetBytes(textSM2SignData.Text);
                    var signatureBytes = SM2Provider.Sign(dataBytes, privateKey, signFormat);
                    signature = CryptoCommonUtil.BytesToString(signatureBytes, OutputFormat.Base64);
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

                string formatText = comboSM2KeyFormat.SelectedItem?.ToString() ?? "";
                string signFormatText = comboSM2SignFormat.SelectedItem?.ToString() ?? "";

                SM2Provider.SM2SignatureFormat signFormat = (SM2Provider.SM2SignatureFormat)Enum.Parse(typeof(SM2Provider.SM2SignatureFormat), signFormatText);

                bool verifyResult;
                if (formatText == "Base64")
                {
                    // 使用接口方法进行验签
                    var sm2Provider = new SM2Provider();
                    verifyResult = sm2Provider.Verify(textSM2SignData.Text, textSM2Signature.Text, textSM2PublicKey.Text, SignatureAlgorithm.SM3withSM2, InputFormat.Base64);
                }
                else // Hex
                {
                    var publicKey = SM2Provider.ParsePublicKeyFromHex(textSM2PublicKey.Text);
                    var dataBytes = Encoding.UTF8.GetBytes(textSM2SignData.Text);
                    var signatureBytes = CryptoCommonUtil.StringToBytes(textSM2Signature.Text, InputFormat.Base64);
                    verifyResult = SM2Provider.Verify(dataBytes, signatureBytes, publicKey, signFormat);
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
    }
}