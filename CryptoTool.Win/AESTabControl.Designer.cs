namespace CryptoTool.Win
{
    partial class AESTabControl : UserControl
    {
        /// <summary> 
        /// 必需的设计器变量。
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary> 
        /// 清理所有正在使用的资源。
        /// </summary>
        /// <param name="disposing">如果应释放托管资源，为 true；否则为 false。</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region 组件设计器生成的代码

        /// <summary> 
        /// 设计器支持所需的方法 - 不要修改
        /// 使用代码编辑器修改此方法的内容。
        /// </summary>
        private void InitializeComponent()
        {
            mainTableLayout = new TableLayoutPanel();
            groupBoxAESKeys = new GroupBox();
            tableLayoutAESKeys = new TableLayoutPanel();
            panelAESKeyControls = new Panel();
            btnGenerateAESKey = new Button();
            comboAESKeyFormat = new ComboBox();
            labelAESKeyFormat = new Label();
            comboAESKeySize = new ComboBox();
            labelAESKeySize = new Label();
            labelAESKey = new Label();
            panelAESKey = new Panel();
            textAESKey = new TextBox();
            panelAESIVControls = new Panel();
            btnGenerateAESIV = new Button();
            comboAESIVFormat = new ComboBox();
            labelAESIVFormat = new Label();
            labelAESIV = new Label();
            panelAESIV = new Panel();
            textAESIV = new TextBox();
            groupBoxAESEncrypt = new GroupBox();
            tableLayoutAESEncrypt = new TableLayoutPanel();
            panelAESEncryptControls = new Panel();
            btnDecryptFile = new Button();
            btnEncryptFile = new Button();
            btnAESDecrypt = new Button();
            btnAESEncrypt = new Button();
            comboAESCiphertextFormat = new ComboBox();
            labelAESCiphertextFormat = new Label();
            comboAESPlaintextFormat = new ComboBox();
            labelAESPlaintextFormat = new Label();
            comboAESPadding = new ComboBox();
            labelAESPadding = new Label();
            comboAESMode = new ComboBox();
            labelAESMode = new Label();
            labelPlaintext = new Label();
            textAESPlainText = new TextBox();
            labelCiphertext = new Label();
            textAESCipherText = new TextBox();
            mainTableLayout.SuspendLayout();
            groupBoxAESKeys.SuspendLayout();
            tableLayoutAESKeys.SuspendLayout();
            panelAESKeyControls.SuspendLayout();
            panelAESKey.SuspendLayout();
            panelAESIVControls.SuspendLayout();
            panelAESIV.SuspendLayout();
            groupBoxAESEncrypt.SuspendLayout();
            tableLayoutAESEncrypt.SuspendLayout();
            panelAESEncryptControls.SuspendLayout();
            SuspendLayout();
            // 
            // mainTableLayout
            // 
            mainTableLayout.ColumnCount = 1;
            mainTableLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            mainTableLayout.Controls.Add(groupBoxAESKeys, 0, 0);
            mainTableLayout.Controls.Add(groupBoxAESEncrypt, 0, 1);
            mainTableLayout.Dock = DockStyle.Fill;
            mainTableLayout.Location = new Point(0, 0);
            mainTableLayout.Name = "mainTableLayout";
            mainTableLayout.Padding = new Padding(6, 7, 6, 7);
            mainTableLayout.RowCount = 2;
            mainTableLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 35F));
            mainTableLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 65F));
            mainTableLayout.Size = new Size(994, 510);
            mainTableLayout.TabIndex = 0;
            // 
            // groupBoxAESKeys
            // 
            groupBoxAESKeys.Controls.Add(tableLayoutAESKeys);
            groupBoxAESKeys.Dock = DockStyle.Fill;
            groupBoxAESKeys.Location = new Point(9, 10);
            groupBoxAESKeys.Name = "groupBoxAESKeys";
            groupBoxAESKeys.Padding = new Padding(6, 7, 6, 7);
            groupBoxAESKeys.Size = new Size(976, 167);
            groupBoxAESKeys.TabIndex = 0;
            groupBoxAESKeys.TabStop = false;
            groupBoxAESKeys.Text = "AES密钥生成";
            // 
            // tableLayoutAESKeys
            // 
            tableLayoutAESKeys.ColumnCount = 1;
            tableLayoutAESKeys.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            tableLayoutAESKeys.Controls.Add(panelAESKeyControls, 0, 0);
            tableLayoutAESKeys.Controls.Add(labelAESKey, 0, 1);
            tableLayoutAESKeys.Controls.Add(panelAESKey, 0, 2);
            tableLayoutAESKeys.Controls.Add(panelAESIVControls, 0, 3);
            tableLayoutAESKeys.Controls.Add(labelAESIV, 0, 4);
            tableLayoutAESKeys.Controls.Add(panelAESIV, 0, 5);
            tableLayoutAESKeys.Dock = DockStyle.Fill;
            tableLayoutAESKeys.Location = new Point(6, 23);
            tableLayoutAESKeys.Margin = new Padding(2, 3, 2, 3);
            tableLayoutAESKeys.Name = "tableLayoutAESKeys";
            tableLayoutAESKeys.RowCount = 6;
            tableLayoutAESKeys.RowStyles.Add(new RowStyle(SizeType.Absolute, 34F));
            tableLayoutAESKeys.RowStyles.Add(new RowStyle(SizeType.Absolute, 21F));
            tableLayoutAESKeys.RowStyles.Add(new RowStyle(SizeType.Absolute, 30F));
            tableLayoutAESKeys.RowStyles.Add(new RowStyle(SizeType.Absolute, 34F));
            tableLayoutAESKeys.RowStyles.Add(new RowStyle(SizeType.Absolute, 21F));
            tableLayoutAESKeys.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
            tableLayoutAESKeys.Size = new Size(964, 137);
            tableLayoutAESKeys.TabIndex = 0;
            // 
            // panelAESKeyControls
            // 
            panelAESKeyControls.Controls.Add(btnGenerateAESKey);
            panelAESKeyControls.Controls.Add(comboAESKeyFormat);
            panelAESKeyControls.Controls.Add(labelAESKeyFormat);
            panelAESKeyControls.Controls.Add(comboAESKeySize);
            panelAESKeyControls.Controls.Add(labelAESKeySize);
            panelAESKeyControls.Dock = DockStyle.Fill;
            panelAESKeyControls.Location = new Point(2, 3);
            panelAESKeyControls.Margin = new Padding(2, 3, 2, 3);
            panelAESKeyControls.Name = "panelAESKeyControls";
            panelAESKeyControls.Size = new Size(960, 28);
            panelAESKeyControls.TabIndex = 0;
            // 
            // btnGenerateAESKey
            // 
            btnGenerateAESKey.Location = new Point(342, 2);
            btnGenerateAESKey.Name = "btnGenerateAESKey";
            btnGenerateAESKey.Size = new Size(80, 26);
            btnGenerateAESKey.TabIndex = 0;
            btnGenerateAESKey.Text = "生成密钥";
            btnGenerateAESKey.UseVisualStyleBackColor = true;
            btnGenerateAESKey.Click += btnGenerateAESKey_Click;
            // 
            // comboAESKeyFormat
            // 
            comboAESKeyFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboAESKeyFormat.FormattingEnabled = true;
            comboAESKeyFormat.Items.AddRange(new object[] { "Base64", "Hex" });
            comboAESKeyFormat.Location = new Point(233, 3);
            comboAESKeyFormat.Name = "comboAESKeyFormat";
            comboAESKeyFormat.Size = new Size(100, 25);
            comboAESKeyFormat.TabIndex = 10;
            // 
            // labelAESKeyFormat
            // 
            labelAESKeyFormat.AutoSize = true;
            labelAESKeyFormat.Location = new Point(171, 7);
            labelAESKeyFormat.Name = "labelAESKeyFormat";
            labelAESKeyFormat.Size = new Size(59, 17);
            labelAESKeyFormat.TabIndex = 11;
            labelAESKeyFormat.Text = "密钥格式:";
            // 
            // comboAESKeySize
            // 
            comboAESKeySize.DropDownStyle = ComboBoxStyle.DropDownList;
            comboAESKeySize.FormattingEnabled = true;
            comboAESKeySize.Items.AddRange(new object[] { "AES128", "AES192", "AES256" });
            comboAESKeySize.Location = new Point(62, 3);
            comboAESKeySize.Name = "comboAESKeySize";
            comboAESKeySize.Size = new Size(100, 25);
            comboAESKeySize.TabIndex = 8;
            // 
            // labelAESKeySize
            // 
            labelAESKeySize.AutoSize = true;
            labelAESKeySize.Location = new Point(0, 7);
            labelAESKeySize.Name = "labelAESKeySize";
            labelAESKeySize.Size = new Size(59, 17);
            labelAESKeySize.TabIndex = 9;
            labelAESKeySize.Text = "密钥长度:";
            // 
            // labelAESKey
            // 
            labelAESKey.AutoSize = true;
            labelAESKey.Dock = DockStyle.Bottom;
            labelAESKey.Location = new Point(3, 38);
            labelAESKey.Name = "labelAESKey";
            labelAESKey.Size = new Size(958, 17);
            labelAESKey.TabIndex = 3;
            labelAESKey.Text = "AES密钥:";
            // 
            // panelAESKey
            // 
            panelAESKey.Controls.Add(textAESKey);
            panelAESKey.Dock = DockStyle.Fill;
            panelAESKey.Location = new Point(2, 58);
            panelAESKey.Margin = new Padding(2, 3, 2, 3);
            panelAESKey.Name = "panelAESKey";
            panelAESKey.Size = new Size(960, 24);
            panelAESKey.TabIndex = 4;
            // 
            // textAESKey
            // 
            textAESKey.Dock = DockStyle.Fill;
            textAESKey.Location = new Point(0, 0);
            textAESKey.Name = "textAESKey";
            textAESKey.Size = new Size(960, 23);
            textAESKey.TabIndex = 2;
            // 
            // panelAESIVControls
            // 
            panelAESIVControls.Controls.Add(btnGenerateAESIV);
            panelAESIVControls.Controls.Add(comboAESIVFormat);
            panelAESIVControls.Controls.Add(labelAESIVFormat);
            panelAESIVControls.Dock = DockStyle.Fill;
            panelAESIVControls.Location = new Point(2, 88);
            panelAESIVControls.Margin = new Padding(2, 3, 2, 3);
            panelAESIVControls.Name = "panelAESIVControls";
            panelAESIVControls.Size = new Size(960, 28);
            panelAESIVControls.TabIndex = 1;
            // 
            // btnGenerateAESIV
            // 
            btnGenerateAESIV.Location = new Point(171, 2);
            btnGenerateAESIV.Name = "btnGenerateAESIV";
            btnGenerateAESIV.Size = new Size(80, 26);
            btnGenerateAESIV.TabIndex = 1;
            btnGenerateAESIV.Text = "生成向量";
            btnGenerateAESIV.UseVisualStyleBackColor = true;
            btnGenerateAESIV.Click += btnGenerateAESIV_Click;
            // 
            // comboAESIVFormat
            // 
            comboAESIVFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboAESIVFormat.FormattingEnabled = true;
            comboAESIVFormat.Items.AddRange(new object[] { "Base64", "Hex" });
            comboAESIVFormat.Location = new Point(62, 3);
            comboAESIVFormat.Name = "comboAESIVFormat";
            comboAESIVFormat.Size = new Size(100, 25);
            comboAESIVFormat.TabIndex = 10;
            // 
            // labelAESIVFormat
            // 
            labelAESIVFormat.AutoSize = true;
            labelAESIVFormat.Location = new Point(0, 7);
            labelAESIVFormat.Name = "labelAESIVFormat";
            labelAESIVFormat.Size = new Size(59, 17);
            labelAESIVFormat.TabIndex = 11;
            labelAESIVFormat.Text = "向量格式:";
            // 
            // labelAESIV
            // 
            labelAESIV.AutoSize = true;
            labelAESIV.Dock = DockStyle.Bottom;
            labelAESIV.Location = new Point(3, 123);
            labelAESIV.Name = "labelAESIV";
            labelAESIV.Size = new Size(958, 17);
            labelAESIV.TabIndex = 5;
            labelAESIV.Text = "初始向量:";
            // 
            // panelAESIV
            // 
            panelAESIV.Controls.Add(textAESIV);
            panelAESIV.Dock = DockStyle.Fill;
            panelAESIV.Location = new Point(2, 143);
            panelAESIV.Margin = new Padding(2, 3, 2, 3);
            panelAESIV.Name = "panelAESIV";
            panelAESIV.Size = new Size(960, 1);
            panelAESIV.TabIndex = 6;
            // 
            // textAESIV
            // 
            textAESIV.Dock = DockStyle.Fill;
            textAESIV.Location = new Point(0, 0);
            textAESIV.Name = "textAESIV";
            textAESIV.Size = new Size(960, 23);
            textAESIV.TabIndex = 4;
            // 
            // groupBoxAESEncrypt
            // 
            groupBoxAESEncrypt.Controls.Add(tableLayoutAESEncrypt);
            groupBoxAESEncrypt.Dock = DockStyle.Fill;
            groupBoxAESEncrypt.Location = new Point(9, 183);
            groupBoxAESEncrypt.Name = "groupBoxAESEncrypt";
            groupBoxAESEncrypt.Padding = new Padding(6, 7, 6, 7);
            groupBoxAESEncrypt.Size = new Size(976, 317);
            groupBoxAESEncrypt.TabIndex = 1;
            groupBoxAESEncrypt.TabStop = false;
            groupBoxAESEncrypt.Text = "AES加密解密";
            // 
            // tableLayoutAESEncrypt
            // 
            tableLayoutAESEncrypt.ColumnCount = 1;
            tableLayoutAESEncrypt.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            tableLayoutAESEncrypt.Controls.Add(panelAESEncryptControls, 0, 0);
            tableLayoutAESEncrypt.Controls.Add(labelPlaintext, 0, 1);
            tableLayoutAESEncrypt.Controls.Add(textAESPlainText, 0, 2);
            tableLayoutAESEncrypt.Controls.Add(labelCiphertext, 0, 3);
            tableLayoutAESEncrypt.Controls.Add(textAESCipherText, 0, 4);
            tableLayoutAESEncrypt.Dock = DockStyle.Fill;
            tableLayoutAESEncrypt.Location = new Point(6, 23);
            tableLayoutAESEncrypt.Margin = new Padding(2, 3, 2, 3);
            tableLayoutAESEncrypt.Name = "tableLayoutAESEncrypt";
            tableLayoutAESEncrypt.RowCount = 5;
            tableLayoutAESEncrypt.RowStyles.Add(new RowStyle(SizeType.Absolute, 68F));
            tableLayoutAESEncrypt.RowStyles.Add(new RowStyle(SizeType.Absolute, 21F));
            tableLayoutAESEncrypt.RowStyles.Add(new RowStyle(SizeType.Percent, 50F));
            tableLayoutAESEncrypt.RowStyles.Add(new RowStyle(SizeType.Absolute, 21F));
            tableLayoutAESEncrypt.RowStyles.Add(new RowStyle(SizeType.Percent, 50F));
            tableLayoutAESEncrypt.Size = new Size(964, 287);
            tableLayoutAESEncrypt.TabIndex = 0;
            // 
            // panelAESEncryptControls
            // 
            panelAESEncryptControls.Controls.Add(btnDecryptFile);
            panelAESEncryptControls.Controls.Add(btnEncryptFile);
            panelAESEncryptControls.Controls.Add(btnAESDecrypt);
            panelAESEncryptControls.Controls.Add(btnAESEncrypt);
            panelAESEncryptControls.Controls.Add(comboAESCiphertextFormat);
            panelAESEncryptControls.Controls.Add(labelAESCiphertextFormat);
            panelAESEncryptControls.Controls.Add(comboAESPlaintextFormat);
            panelAESEncryptControls.Controls.Add(labelAESPlaintextFormat);
            panelAESEncryptControls.Controls.Add(comboAESPadding);
            panelAESEncryptControls.Controls.Add(labelAESPadding);
            panelAESEncryptControls.Controls.Add(comboAESMode);
            panelAESEncryptControls.Controls.Add(labelAESMode);
            panelAESEncryptControls.Dock = DockStyle.Fill;
            panelAESEncryptControls.Location = new Point(2, 3);
            panelAESEncryptControls.Margin = new Padding(2, 3, 2, 3);
            panelAESEncryptControls.Name = "panelAESEncryptControls";
            panelAESEncryptControls.Size = new Size(960, 62);
            panelAESEncryptControls.TabIndex = 0;
            // 
            // btnDecryptFile
            // 
            btnDecryptFile.Location = new Point(778, 33);
            btnDecryptFile.Name = "btnDecryptFile";
            btnDecryptFile.Size = new Size(75, 26);
            btnDecryptFile.TabIndex = 3;
            btnDecryptFile.Text = "解密文件";
            btnDecryptFile.UseVisualStyleBackColor = true;
            btnDecryptFile.Click += btnDecryptFile_Click;
            // 
            // btnEncryptFile
            // 
            btnEncryptFile.Location = new Point(684, 34);
            btnEncryptFile.Name = "btnEncryptFile";
            btnEncryptFile.Size = new Size(72, 26);
            btnEncryptFile.TabIndex = 2;
            btnEncryptFile.Text = "加密文件";
            btnEncryptFile.UseVisualStyleBackColor = true;
            btnEncryptFile.Click += btnEncryptFile_Click;
            // 
            // btnAESDecrypt
            // 
            btnAESDecrypt.Location = new Point(778, 2);
            btnAESDecrypt.Name = "btnAESDecrypt";
            btnAESDecrypt.Size = new Size(75, 26);
            btnAESDecrypt.TabIndex = 1;
            btnAESDecrypt.Text = "解密";
            btnAESDecrypt.UseVisualStyleBackColor = true;
            btnAESDecrypt.Click += btnAESDecrypt_Click;
            // 
            // btnAESEncrypt
            // 
            btnAESEncrypt.Location = new Point(684, 2);
            btnAESEncrypt.Name = "btnAESEncrypt";
            btnAESEncrypt.Size = new Size(72, 26);
            btnAESEncrypt.TabIndex = 0;
            btnAESEncrypt.Text = "加密";
            btnAESEncrypt.UseVisualStyleBackColor = true;
            btnAESEncrypt.Click += btnAESEncrypt_Click;
            // 
            // comboAESCiphertextFormat
            // 
            comboAESCiphertextFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboAESCiphertextFormat.FormattingEnabled = true;
            comboAESCiphertextFormat.Items.AddRange(new object[] { "Base64", "Hex" });
            comboAESCiphertextFormat.Location = new Point(576, 3);
            comboAESCiphertextFormat.Name = "comboAESCiphertextFormat";
            comboAESCiphertextFormat.Size = new Size(100, 25);
            comboAESCiphertextFormat.TabIndex = 8;
            // 
            // labelAESCiphertextFormat
            // 
            labelAESCiphertextFormat.AutoSize = true;
            labelAESCiphertextFormat.Location = new Point(513, 7);
            labelAESCiphertextFormat.Name = "labelAESCiphertextFormat";
            labelAESCiphertextFormat.Size = new Size(59, 17);
            labelAESCiphertextFormat.TabIndex = 9;
            labelAESCiphertextFormat.Text = "密文格式:";
            // 
            // comboAESPlaintextFormat
            // 
            comboAESPlaintextFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboAESPlaintextFormat.FormattingEnabled = true;
            comboAESPlaintextFormat.Items.AddRange(new object[] { "Text", "Base64", "Hex" });
            comboAESPlaintextFormat.Location = new Point(404, 3);
            comboAESPlaintextFormat.Name = "comboAESPlaintextFormat";
            comboAESPlaintextFormat.Size = new Size(100, 25);
            comboAESPlaintextFormat.TabIndex = 10;
            // 
            // labelAESPlaintextFormat
            // 
            labelAESPlaintextFormat.AutoSize = true;
            labelAESPlaintextFormat.Location = new Point(342, 7);
            labelAESPlaintextFormat.Name = "labelAESPlaintextFormat";
            labelAESPlaintextFormat.Size = new Size(59, 17);
            labelAESPlaintextFormat.TabIndex = 11;
            labelAESPlaintextFormat.Text = "明文格式:";
            // 
            // comboAESPadding
            // 
            comboAESPadding.DropDownStyle = ComboBoxStyle.DropDownList;
            comboAESPadding.FormattingEnabled = true;
            comboAESPadding.Items.AddRange(new object[] { "PKCS7", "PKCS5", "Zeros", "ISO10126", "ANSIX923", "None" });
            comboAESPadding.Location = new Point(233, 3);
            comboAESPadding.Name = "comboAESPadding";
            comboAESPadding.Size = new Size(100, 25);
            comboAESPadding.TabIndex = 6;
            // 
            // labelAESPadding
            // 
            labelAESPadding.AutoSize = true;
            labelAESPadding.Location = new Point(171, 7);
            labelAESPadding.Name = "labelAESPadding";
            labelAESPadding.Size = new Size(59, 17);
            labelAESPadding.TabIndex = 7;
            labelAESPadding.Text = "填充模式:";
            // 
            // comboAESMode
            // 
            comboAESMode.DropDownStyle = ComboBoxStyle.DropDownList;
            comboAESMode.FormattingEnabled = true;
            comboAESMode.Items.AddRange(new object[] { "ECB", "CBC", "CFB", "OFB" });
            comboAESMode.Location = new Point(62, 3);
            comboAESMode.Name = "comboAESMode";
            comboAESMode.Size = new Size(100, 25);
            comboAESMode.TabIndex = 4;
            comboAESMode.SelectedIndexChanged += comboAESMode_SelectedIndexChanged;
            // 
            // labelAESMode
            // 
            labelAESMode.AutoSize = true;
            labelAESMode.Location = new Point(0, 7);
            labelAESMode.Name = "labelAESMode";
            labelAESMode.Size = new Size(59, 17);
            labelAESMode.TabIndex = 5;
            labelAESMode.Text = "加密模式:";
            // 
            // labelPlaintext
            // 
            labelPlaintext.AutoSize = true;
            labelPlaintext.Dock = DockStyle.Bottom;
            labelPlaintext.Location = new Point(3, 72);
            labelPlaintext.Name = "labelPlaintext";
            labelPlaintext.Size = new Size(958, 17);
            labelPlaintext.TabIndex = 3;
            labelPlaintext.Text = "明文:";
            // 
            // textAESPlainText
            // 
            textAESPlainText.Dock = DockStyle.Fill;
            textAESPlainText.Location = new Point(3, 92);
            textAESPlainText.Multiline = true;
            textAESPlainText.Name = "textAESPlainText";
            textAESPlainText.ScrollBars = ScrollBars.Both;
            textAESPlainText.Size = new Size(958, 82);
            textAESPlainText.TabIndex = 2;
            // 
            // labelCiphertext
            // 
            labelCiphertext.AutoSize = true;
            labelCiphertext.Dock = DockStyle.Bottom;
            labelCiphertext.Location = new Point(3, 181);
            labelCiphertext.Name = "labelCiphertext";
            labelCiphertext.Size = new Size(958, 17);
            labelCiphertext.TabIndex = 5;
            labelCiphertext.Text = "密文:";
            // 
            // textAESCipherText
            // 
            textAESCipherText.Dock = DockStyle.Fill;
            textAESCipherText.Location = new Point(3, 201);
            textAESCipherText.Multiline = true;
            textAESCipherText.Name = "textAESCipherText";
            textAESCipherText.ScrollBars = ScrollBars.Both;
            textAESCipherText.Size = new Size(958, 83);
            textAESCipherText.TabIndex = 3;
            // 
            // AESTabControl
            // 
            AutoScaleDimensions = new SizeF(7F, 17F);
            AutoScaleMode = AutoScaleMode.Font;
            Controls.Add(mainTableLayout);
            Name = "AESTabControl";
            Size = new Size(994, 510);
            mainTableLayout.ResumeLayout(false);
            groupBoxAESKeys.ResumeLayout(false);
            tableLayoutAESKeys.ResumeLayout(false);
            tableLayoutAESKeys.PerformLayout();
            panelAESKeyControls.ResumeLayout(false);
            panelAESKeyControls.PerformLayout();
            panelAESKey.ResumeLayout(false);
            panelAESKey.PerformLayout();
            panelAESIVControls.ResumeLayout(false);
            panelAESIVControls.PerformLayout();
            panelAESIV.ResumeLayout(false);
            panelAESIV.PerformLayout();
            groupBoxAESEncrypt.ResumeLayout(false);
            tableLayoutAESEncrypt.ResumeLayout(false);
            tableLayoutAESEncrypt.PerformLayout();
            panelAESEncryptControls.ResumeLayout(false);
            panelAESEncryptControls.PerformLayout();
            ResumeLayout(false);
        }

        #endregion

        private TableLayoutPanel mainTableLayout;
        private GroupBox groupBoxAESKeys;
        private TableLayoutPanel tableLayoutAESKeys;
        private Panel panelAESKeyControls;
        private Label labelAESKeySize;
        private ComboBox comboAESKeySize;
        private Label labelAESKeyFormat;
        private ComboBox comboAESKeyFormat;
        private Button btnGenerateAESKey;
        private Label labelAESKey;
        private Panel panelAESKey;
        private TextBox textAESKey;
        private Panel panelAESIVControls;
        private Label labelAESIVFormat;
        private ComboBox comboAESIVFormat;
        private Button btnGenerateAESIV;
        private Label labelAESIV;
        private Panel panelAESIV;
        private TextBox textAESIV;
        private GroupBox groupBoxAESEncrypt;
        private TableLayoutPanel tableLayoutAESEncrypt;
        private Panel panelAESEncryptControls;
        private Button btnDecryptFile;
        private Button btnEncryptFile;
        private Button btnAESDecrypt;
        private Button btnAESEncrypt;
        private ComboBox comboAESCiphertextFormat;
        private Label labelAESCiphertextFormat;
        private ComboBox comboAESPlaintextFormat;
        private Label labelAESPlaintextFormat;
        private ComboBox comboAESPadding;
        private Label labelAESPadding;
        private ComboBox comboAESMode;
        private Label labelAESMode;
        private Label labelPlaintext;
        private TextBox textAESPlainText;
        private Label labelCiphertext;
        private TextBox textAESCipherText;
    }
}