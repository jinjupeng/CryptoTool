using CryptoTool.Common;
using System;
using System.Drawing;
using System.IO;
using System.Text;
using System.Windows.Forms;

namespace CryptoTool.Win
{
    public partial class AESTabControl : UserControl
    {
        public event Action<string> StatusChanged;

        public AESTabControl()
        {
            InitializeComponent();
            InitializeDefaults();
        }

        private void InitializeDefaults()
        {
            comboAESMode.SelectedIndex = 1; // CBC
            comboAESPadding.SelectedIndex = 0; // PKCS7
            comboAESKeyFormat.SelectedIndex = 0; // Base64
            comboAESIVFormat.SelectedIndex = 0; // Base64
            comboAESPlaintextFormat.SelectedIndex = 0; // Text
            comboAESCiphertextFormat.SelectedIndex = 0; // Base64
            comboAESKeySize.SelectedIndex = 2; // AES256
        }

        private void SetStatus(string message)
        {
            StatusChanged?.Invoke(message);
        }

        #region AES����

        private void btnGenerateAESKey_Click(object sender, EventArgs e)
        {
            try
            {
                SetStatus("��������AES��Կ...");

                string keySizeText = comboAESKeySize.SelectedItem.ToString();
                AESUtil.AESKeySize keySize = (AESUtil.AESKeySize)Enum.Parse(typeof(AESUtil.AESKeySize), keySizeText);

                string key = AESUtil.GenerateKey(keySize);
                textAESKey.Text = key;
                SetStatus($"AES��Կ������� - {keySizeText}λ");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"����AES��Կʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("����AES��Կʧ��");
            }
        }

        private void btnGenerateAESIV_Click(object sender, EventArgs e)
        {
            try
            {
                SetStatus("��������AES��ʼ����...");

                string iv = AESUtil.GenerateIV();
                textAESIV.Text = iv;
                SetStatus("AES��ʼ�����������");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"����AES��ʼ����ʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("����AES��ʼ����ʧ��");
            }
        }

        private void btnAESEncrypt_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textAESPlainText.Text))
                {
                    MessageBox.Show("���������ģ�", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textAESKey.Text))
                {
                    MessageBox.Show("�������ɻ�����AES��Կ��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                string mode = comboAESMode.SelectedItem.ToString();
                if (mode != "ECB" && string.IsNullOrEmpty(textAESIV.Text))
                {
                    MessageBox.Show($"{mode}ģʽ��Ҫ��ʼ�������������ɻ������ʼ������", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("���ڽ���AES����...");

                string modeText = comboAESMode.SelectedItem.ToString();
                string paddingText = comboAESPadding.SelectedItem.ToString();
                string outputFormatText = comboAESCiphertextFormat.SelectedItem.ToString();

                AESUtil.AESMode aesMode = (AESUtil.AESMode)Enum.Parse(typeof(AESUtil.AESMode), modeText);
                AESUtil.AESPadding aesPadding = (AESUtil.AESPadding)Enum.Parse(typeof(AESUtil.AESPadding), paddingText);
                AESUtil.OutputFormat outputFormat = (AESUtil.OutputFormat)Enum.Parse(typeof(AESUtil.OutputFormat), outputFormatText);

                string plaintext = GetPlaintextFromFormat();
                string iv = string.IsNullOrEmpty(textAESIV.Text) ? null : textAESIV.Text;

                string cipherText = AESUtil.EncryptByAES(plaintext, textAESKey.Text, aesMode, aesPadding, outputFormat, iv);
                textAESCipherText.Text = cipherText;

                SetStatus($"AES������� - ʹ��{modeText}ģʽ�����{outputFormatText}��ʽ");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"AES����ʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("AES����ʧ��");
            }
        }

        private void btnAESDecrypt_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textAESCipherText.Text))
                {
                    MessageBox.Show("���������ģ�", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textAESKey.Text))
                {
                    MessageBox.Show("�������ɻ�����AES��Կ��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                string mode = comboAESMode.SelectedItem.ToString();
                if (mode != "ECB" && string.IsNullOrEmpty(textAESIV.Text))
                {
                    MessageBox.Show($"{mode}ģʽ��Ҫ��ʼ�������������ɻ������ʼ������", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("���ڽ���AES����...");

                string modeText = comboAESMode.SelectedItem.ToString();
                string paddingText = comboAESPadding.SelectedItem.ToString();
                string outputFormatText = comboAESCiphertextFormat.SelectedItem.ToString();

                AESUtil.AESMode aesMode = (AESUtil.AESMode)Enum.Parse(typeof(AESUtil.AESMode), modeText);
                AESUtil.AESPadding aesPadding = (AESUtil.AESPadding)Enum.Parse(typeof(AESUtil.AESPadding), paddingText);
                AESUtil.OutputFormat inputFormat = (AESUtil.OutputFormat)Enum.Parse(typeof(AESUtil.OutputFormat), outputFormatText);

                string iv = string.IsNullOrEmpty(textAESIV.Text) ? null : textAESIV.Text;

                string plainText = AESUtil.DecryptByAES(textAESCipherText.Text, textAESKey.Text, aesMode, aesPadding, inputFormat, iv);
                SetPlaintextFromFormat(plainText);

                SetStatus($"AES������� - ʹ��{modeText}ģʽ������{outputFormatText}��ʽ");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"AES����ʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("AES����ʧ��");
            }
        }

        private void comboAESMode_SelectedIndexChanged(object sender, EventArgs e)
        {
            // ��ѡ��ECBģʽʱ�����ó�ʼ������ؿؼ�
            bool needsIV = comboAESMode.SelectedItem.ToString() != "ECB";
            textAESIV.Enabled = needsIV;
            btnGenerateAESIV.Enabled = needsIV;
            comboAESIVFormat.Enabled = needsIV;
            labelAESIVFormat.Enabled = needsIV;

            if (!needsIV)
            {
                textAESIV.Text = "";
            }
        }

        #endregion

        #region �ļ�����

        private void btnEncryptFile_Click(object sender, EventArgs e)
        {
            try
            {
                using (OpenFileDialog openDialog = new OpenFileDialog())
                {
                    openDialog.Title = "ѡ��Ҫ���ܵ��ļ�";
                    openDialog.Filter = "�����ļ�|*.*";
                    
                    if (openDialog.ShowDialog() != DialogResult.OK)
                        return;

                    using (SaveFileDialog saveDialog = new SaveFileDialog())
                    {
                        saveDialog.Title = "��������ļ�";
                        saveDialog.Filter = "�����ļ�|*.enc|�����ļ�|*.*";
                        saveDialog.FileName = Path.GetFileNameWithoutExtension(openDialog.FileName) + ".enc";
                        
                        if (saveDialog.ShowDialog() != DialogResult.OK)
                            return;

                        if (string.IsNullOrEmpty(textAESKey.Text))
                        {
                            MessageBox.Show("�������ɻ�����AES��Կ��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                            return;
                        }

                        string mode = comboAESMode.SelectedItem.ToString();
                        if (mode != "ECB" && string.IsNullOrEmpty(textAESIV.Text))
                        {
                            MessageBox.Show($"{mode}ģʽ��Ҫ��ʼ�������������ɻ������ʼ������", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                            return;
                        }

                        SetStatus("���ڼ����ļ�...");

                        string modeText = comboAESMode.SelectedItem.ToString();
                        string paddingText = comboAESPadding.SelectedItem.ToString();

                        AESUtil.AESMode aesMode = (AESUtil.AESMode)Enum.Parse(typeof(AESUtil.AESMode), modeText);
                        AESUtil.AESPadding aesPadding = (AESUtil.AESPadding)Enum.Parse(typeof(AESUtil.AESPadding), paddingText);

                        string iv = string.IsNullOrEmpty(textAESIV.Text) ? null : textAESIV.Text;

                        AESUtil.EncryptFile(openDialog.FileName, saveDialog.FileName, textAESKey.Text, aesMode, aesPadding, iv);

                        SetStatus($"�ļ�������ɣ�{saveDialog.FileName}");
                        MessageBox.Show("�ļ�������ɣ�", "�ɹ�", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"�ļ�����ʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("�ļ�����ʧ��");
            }
        }

        private void btnDecryptFile_Click(object sender, EventArgs e)
        {
            try
            {
                using (OpenFileDialog openDialog = new OpenFileDialog())
                {
                    openDialog.Title = "ѡ��Ҫ���ܵ��ļ�";
                    openDialog.Filter = "�����ļ�|*.enc|�����ļ�|*.*";
                    
                    if (openDialog.ShowDialog() != DialogResult.OK)
                        return;

                    using (SaveFileDialog saveDialog = new SaveFileDialog())
                    {
                        saveDialog.Title = "��������ļ�";
                        saveDialog.Filter = "�����ļ�|*.*";
                        string originalName = Path.GetFileNameWithoutExtension(openDialog.FileName);
                        if (originalName.EndsWith(".enc"))
                            originalName = originalName.Substring(0, originalName.Length - 4);
                        saveDialog.FileName = originalName;
                        
                        if (saveDialog.ShowDialog() != DialogResult.OK)
                            return;

                        if (string.IsNullOrEmpty(textAESKey.Text))
                        {
                            MessageBox.Show("��������AES��Կ��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                            return;
                        }

                        string mode = comboAESMode.SelectedItem.ToString();
                        if (mode != "ECB" && string.IsNullOrEmpty(textAESIV.Text))
                        {
                            MessageBox.Show($"{mode}ģʽ��Ҫ��ʼ���������������ʼ������", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                            return;
                        }

                        SetStatus("���ڽ����ļ�...");

                        string modeText = comboAESMode.SelectedItem.ToString();
                        string paddingText = comboAESPadding.SelectedItem.ToString();

                        AESUtil.AESMode aesMode = (AESUtil.AESMode)Enum.Parse(typeof(AESUtil.AESMode), modeText);
                        AESUtil.AESPadding aesPadding = (AESUtil.AESPadding)Enum.Parse(typeof(AESUtil.AESPadding), paddingText);

                        string iv = string.IsNullOrEmpty(textAESIV.Text) ? null : textAESIV.Text;

                        AESUtil.DecryptFile(openDialog.FileName, saveDialog.FileName, textAESKey.Text, aesMode, aesPadding, iv);

                        SetStatus($"�ļ�������ɣ�{saveDialog.FileName}");
                        MessageBox.Show("�ļ�������ɣ�", "�ɹ�", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"�ļ�����ʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("�ļ�����ʧ��");
            }
        }

        #endregion

        #region ��������

        private string GetPlaintextFromFormat()
        {
            string plaintextFormat = comboAESPlaintextFormat.SelectedItem.ToString();
            string plaintext = textAESPlainText.Text;

            // �����Text��ʽ��ֱ�ӷ���
            if (plaintextFormat == "Text")
                return plaintext;

            // ������ʽ��ʱֱ�ӷ��أ�����������չ��ʽת������
            return plaintext;
        }

        private void SetPlaintextFromFormat(string decryptedText)
        {
            string plaintextFormat = comboAESPlaintextFormat.SelectedItem.ToString();

            // ���ݸ�ʽ������ʾ����
            if (plaintextFormat == "Text")
            {
                textAESPlainText.Text = decryptedText;
            }
            else if (plaintextFormat == "Base64")
            {
                try
                {
                    byte[] bytes = Encoding.UTF8.GetBytes(decryptedText);
                    textAESPlainText.Text = Convert.ToBase64String(bytes);
                }
                catch
                {
                    textAESPlainText.Text = decryptedText; // ���ת��ʧ�ܣ�ֱ����ʾ
                }
            }
            else if (plaintextFormat == "Hex")
            {
                try
                {
                    byte[] bytes = Encoding.UTF8.GetBytes(decryptedText);
                    textAESPlainText.Text = BitConverter.ToString(bytes).Replace("-", "");
                }
                catch
                {
                    textAESPlainText.Text = decryptedText; // ���ת��ʧ�ܣ�ֱ����ʾ
                }
            }
            else
            {
                textAESPlainText.Text = decryptedText;
            }
        }

        #endregion
    }
}