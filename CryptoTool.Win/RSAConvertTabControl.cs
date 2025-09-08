using CryptoTool.Common;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;

namespace CryptoTool.Win
{
    public partial class RSAConvertTabControl : UserControl
    {
        public event Action<string> StatusChanged;

        // �洢����Ĺ�Կ��˽Կ������֤
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
            // ��ʼ��Ĭ��ֵ
            comboInputKeyType.SelectedIndex = 0; // PKCS1
            comboInputFormat.SelectedIndex = 0; // PEM
            comboOutputKeyType.SelectedIndex = 1; // PKCS8
            comboOutputFormat.SelectedIndex = 0; // PEM
            radioPrivateKey.Checked = true;
            
            // ��ʼ����֤�����ǩ
            labelValidationResult.Text = "��֤���: �ȴ���֤";
            labelValidationResult.ForeColor = Color.Gray;
        }

        private void SetStatus(string message)
        {
            StatusChanged?.Invoke(message);
        }

        #region �¼�����

        private void btnImportFromFile_Click(object sender, EventArgs e)
        {
            try
            {
                using (OpenFileDialog openFileDialog = new OpenFileDialog())
                {
                    openFileDialog.Filter = "��Կ�ļ� (*.txt;*.key;*.pem;*.pub)|*.txt;*.key;*.pem;*.pub|�����ļ� (*.*)|*.*";
                    openFileDialog.Title = "����RSA��Կ�ļ�";

                    if (openFileDialog.ShowDialog() == DialogResult.OK)
                    {
                        string content = File.ReadAllText(openFileDialog.FileName, Encoding.UTF8);
                        textInputKey.Text = content.Trim();
                        
                        // �����ļ������Զ��ж���Կ����
                        AutoDetectKeyType(content);
                        
                        SetStatus("��Կ�ļ�����ɹ�");
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"������Կ�ļ�ʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("������Կ�ļ�ʧ��");
            }
        }

        private void btnValidateKeyPair_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(_publicKeyForValidation) || string.IsNullOrEmpty(_privateKeyForValidation))
                {
                    MessageBox.Show("���ȷֱ��빫Կ��˽Կ������֤��\n\n�������裺\n1. ����˽Կ���������˽Կ��ȡ��Կ��\n2. ��ֱ��빫Կ��˽Կ�ļ�", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }

                SetStatus("������֤��Կ��һ����...");

                bool isValid = ValidateKeyPair(_publicKeyForValidation, _privateKeyForValidation, 
                    _publicKeyFormatForValidation, _publicKeyTypeForValidation,
                    _privateKeyFormatForValidation, _privateKeyTypeForValidation);

                labelValidationResult.Text = $"��֤���: {(isValid ? "��Կ��ƥ��" : "��Կ�Բ�ƥ��")}";
                labelValidationResult.ForeColor = isValid ? Color.Green : Color.Red;

                SetStatus($"��Կ����֤��� - {(isValid ? "ƥ��" : "��ƥ��")}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"��Կ����֤ʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                labelValidationResult.Text = "��֤���: ��֤�쳣";
                labelValidationResult.ForeColor = Color.Red;
                SetStatus("��Կ����֤ʧ��");
            }
        }

        private void btnGetPublicKeyFromPrivate_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textInputKey.Text))
                {
                    MessageBox.Show("��������˽Կ��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (radioPublicKey.Checked)
                {
                    MessageBox.Show("��ѡ��˽Կ���Ͳ�����ȡ��Կ��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("���ڴ�˽Կ��ȡ��Կ...");

                var inputKeyType = (RSAUtil.RSAKeyType)comboInputKeyType.SelectedIndex;
                var inputFormat = (RSAUtil.RSAKeyFormat)comboInputFormat.SelectedIndex;
                var outputKeyType = (RSAUtil.RSAKeyType)comboOutputKeyType.SelectedIndex;
                var outputFormat = (RSAUtil.RSAKeyFormat)comboOutputFormat.SelectedIndex;

                // ����˽Կ
                var privateKey = (RsaPrivateCrtKeyParameters)RSAUtil.ParseKey(
                    textInputKey.Text, true, inputFormat, inputKeyType);

                // ��˽Կ��ȡ��Կ����
                var publicKey = new RsaKeyParameters(false, privateKey.Modulus, privateKey.PublicExponent);

                // ���ɹ�Կ�ַ���
                string publicKeyString = RSAUtil.GeneratePublicKeyString(publicKey, outputFormat, outputKeyType);

                textOutputKey.Text = publicKeyString;

                // �洢��Կ������֤
                _privateKeyForValidation = textInputKey.Text;
                _privateKeyFormatForValidation = inputFormat;
                _privateKeyTypeForValidation = inputKeyType;
                _publicKeyForValidation = publicKeyString;
                _publicKeyFormatForValidation = outputFormat;
                _publicKeyTypeForValidation = outputKeyType;

                // �Զ���֤��Կ��
                labelValidationResult.Text = "��֤���: ��Կ��ƥ�䣨��˽Կ��ȡ��";
                labelValidationResult.ForeColor = Color.Green;

                SetStatus("��˽Կ��ȡ��Կ���");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"��˽Կ��ȡ��Կʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("��˽Կ��ȡ��Կʧ��");
            }
        }

        private void btnConvert_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textInputKey.Text))
                {
                    MessageBox.Show("����������Կ���ݣ�", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("���ڽ��и�ʽת��...");

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

                SetStatus($"��ʽת����� - {inputKeyType}/{inputFormat} -> {outputKeyType}/{outputFormat}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"��ʽת��ʧ�ܣ�{ex.Message}\n\n���飺\n1. ��Կ�����Ƿ���ȷ\n2. ��Կ����ѡ���Ƿ�ƥ��\n3. �����ʽѡ���Ƿ���ȷ", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("��ʽת��ʧ��");
            }
        }

        private void btnClear_Click(object sender, EventArgs e)
        {
            textInputKey.Clear();
            textOutputKey.Clear();
            labelValidationResult.Text = "��֤���: �ȴ���֤";
            labelValidationResult.ForeColor = Color.Gray;
            _publicKeyForValidation = string.Empty;
            _privateKeyForValidation = string.Empty;
            SetStatus("�������������");
        }

        private void btnSaveToFile_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textOutputKey.Text))
                {
                    MessageBox.Show("û�пɱ�������ݣ�", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
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
                    saveFileDialog.Title = "����ת�������Կ";
                    saveFileDialog.FileName = $"rsa_{keyType}_key{extension}";

                    if (saveFileDialog.ShowDialog() == DialogResult.OK)
                    {
                        File.WriteAllText(saveFileDialog.FileName, textOutputKey.Text, Encoding.UTF8);
                        SetStatus("��Կ�ļ�����ɹ�");
                        MessageBox.Show("��Կ�ļ�����ɹ���", "�ɹ�", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"�����ļ�ʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("�����ļ�ʧ��");
            }
        }

        private void btnCopyToClipboard_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textOutputKey.Text))
                {
                    MessageBox.Show("û�пɸ��Ƶ����ݣ�", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                Clipboard.SetText(textOutputKey.Text);
                SetStatus("�Ѹ��Ƶ�������");
                MessageBox.Show("�Ѹ��Ƶ������壡", "�ɹ�", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"���Ƶ�������ʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("���Ƶ�������ʧ��");
            }
        }

        private void textInputKey_TextChanged(object sender, EventArgs e)
        {
            // ��������Կ���ݸı�ʱ���Զ������Կ����
            if (!string.IsNullOrEmpty(textInputKey.Text))
            {
                AutoDetectKeyType(textInputKey.Text);
            }
            else
            {
                // �����֤���
                labelValidationResult.Text = "��֤���: �ȴ���֤";
                labelValidationResult.ForeColor = Color.Gray;
                _publicKeyForValidation = string.Empty;
                _privateKeyForValidation = string.Empty;
            }
        }

        #endregion

        #region ��������

        private void AutoDetectKeyType(string keyContent)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(keyContent))
                    return;

                // ����Ƿ�Ϊ˽Կ
                bool isPrivateKey = keyContent.Contains("PRIVATE KEY") || 
                                   keyContent.Contains("BEGIN RSA PRIVATE KEY") ||
                                   keyContent.Contains("<D>") || // XML��ʽ˽Կ��ʶ
                                   keyContent.Contains("\"d\":"); // JSON��ʽ˽Կ��ʶ

                if (isPrivateKey)
                {
                    radioPrivateKey.Checked = true;
                    
                    // �洢˽Կ������֤
                    _privateKeyForValidation = keyContent;
                    _privateKeyFormatForValidation = DetectKeyFormat(keyContent);
                    _privateKeyTypeForValidation = DetectKeyType(keyContent);
                }
                else
                {
                    radioPublicKey.Checked = true;
                    
                    // �洢��Կ������֤
                    _publicKeyForValidation = keyContent;
                    _publicKeyFormatForValidation = DetectKeyFormat(keyContent);
                    _publicKeyTypeForValidation = DetectKeyType(keyContent);
                }

                // ���������ʽѡ��
                var detectedFormat = DetectKeyFormat(keyContent);
                comboInputFormat.SelectedIndex = (int)detectedFormat;

                // ����������Կ����ѡ��
                var detectedType = DetectKeyType(keyContent);
                comboInputKeyType.SelectedIndex = (int)detectedType;
            }
            catch
            {
                // �Զ����ʧ��ʱ����Ĭ��ֵ
            }
        }

        private RSAUtil.RSAKeyFormat DetectKeyFormat(string keyContent)
        {
            if (keyContent.Contains("-----BEGIN") && keyContent.Contains("-----END"))
                return RSAUtil.RSAKeyFormat.PEM;
            
            // ����Ƿ�Ϊ��Base64��û��PEMͷβ��
            if (IsBase64String(keyContent.Replace("\r", "").Replace("\n", "").Trim()))
                return RSAUtil.RSAKeyFormat.Base64;
            
            // ����Ƿ�ΪHex
            if (IsHexString(keyContent.Replace("\r", "").Replace("\n", "").Replace(" ", "").Replace("-", "")))
                return RSAUtil.RSAKeyFormat.Hex;

            return RSAUtil.RSAKeyFormat.PEM; // Ĭ��
        }

        private RSAUtil.RSAKeyType DetectKeyType(string keyContent)
        {
            // PKCS#8 ��ʶ
            if (keyContent.Contains("BEGIN PRIVATE KEY") || keyContent.Contains("BEGIN PUBLIC KEY"))
                return RSAUtil.RSAKeyType.PKCS8;
            
            // PKCS#1 ��ʶ
            if (keyContent.Contains("BEGIN RSA PRIVATE KEY") || keyContent.Contains("BEGIN RSA PUBLIC KEY"))
                return RSAUtil.RSAKeyType.PKCS1;

            return RSAUtil.RSAKeyType.PKCS1; // Ĭ��
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
                // ������Կ��˽Կ
                var publicKey = (RsaKeyParameters)RSAUtil.ParseKey(publicKeyStr, false, publicKeyFormat, publicKeyType);
                var privateKey = (RsaPrivateCrtKeyParameters)RSAUtil.ParseKey(privateKeyStr, true, privateKeyFormat, privateKeyType);

                // ���ģ���Ƿ�һ��
                if (!publicKey.Modulus.Equals(privateKey.Modulus))
                    return false;

                // ��鹫ָ���Ƿ�һ��
                if (!publicKey.Exponent.Equals(privateKey.PublicExponent))
                    return false;

                // ���мӽ��ܲ�����֤
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
                RSAUtil.RSAKeyFormat.PEM => "PEM�ļ� (*.pem)|*.pem|�����ļ� (*.*)|*.*",
                RSAUtil.RSAKeyFormat.Base64 => "�ı��ļ� (*.txt)|*.txt|�����ļ� (*.*)|*.*",
                RSAUtil.RSAKeyFormat.Hex => "�ı��ļ� (*.txt)|*.txt|�����ļ� (*.*)|*.*",
                _ => "�����ļ� (*.*)|*.*"
            };
        }

        #endregion
    }
}