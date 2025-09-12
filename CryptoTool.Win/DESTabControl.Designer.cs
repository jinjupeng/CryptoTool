namespace CryptoTool.Win
{
    partial class DESTabControl : UserControl
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
            groupBoxDESKeys = new GroupBox();
            tableLayoutDESKeys = new TableLayoutPanel();
            panelDESKeyControls = new Panel();
            btnConvertDESKey = new Button();
            btnGenerateDESKey = new Button();
            comboDESKeyFormat = new ComboBox();
            labelDESKeyFormat = new Label();
            labelDESKey = new Label();
            panelDESKey = new Panel();
            textDESKey = new TextBox();
            panelDESIVControls = new Panel();
            btnConvertDESIV = new Button();
            btnGenerateDESIV = new Button();
            comboDESIVFormat = new ComboBox();
            labelDESIVFormat = new Label();
            labelDESIV = new Label();
            panelDESIV = new Panel();
            textDESIV = new TextBox();
            groupBoxDESEncrypt = new GroupBox();
            tableLayoutDESEncrypt = new TableLayoutPanel();
            panelDESEncryptControls = new Panel();
            btnDecryptFile = new Button();
            btnEncryptFile = new Button();
            btnDESDecrypt = new Button();
            btnDESEncrypt = new Button();
            comboDESCiphertextFormat = new ComboBox();
            labelDESCiphertextFormat = new Label();
            comboDESPlaintextFormat = new ComboBox();
            labelDESPlaintextFormat = new Label();
            comboDESPadding = new ComboBox();
            labelDESPadding = new Label();
            comboDESMode = new ComboBox();
            labelDESMode = new Label();
            labelPlaintext = new Label();
            textDESPlainText = new TextBox();
            labelCiphertext = new Label();
            textDESCipherText = new TextBox();
            mainTableLayout.SuspendLayout();
            groupBoxDESKeys.SuspendLayout();
            tableLayoutDESKeys.SuspendLayout();
            panelDESKeyControls.SuspendLayout();
            panelDESKey.SuspendLayout();
            panelDESIVControls.SuspendLayout();
            panelDESIV.SuspendLayout();
            groupBoxDESEncrypt.SuspendLayout();
            tableLayoutDESEncrypt.SuspendLayout();
            panelDESEncryptControls.SuspendLayout();
            SuspendLayout();
            // 
            // mainTableLayout
            // 
            mainTableLayout.ColumnCount = 1;
            mainTableLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            mainTableLayout.Controls.Add(groupBoxDESKeys, 0, 0);
            mainTableLayout.Controls.Add(groupBoxDESEncrypt, 0, 1);
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
            // groupBoxDESKeys
            // 
            groupBoxDESKeys.Controls.Add(tableLayoutDESKeys);
            groupBoxDESKeys.Dock = DockStyle.Fill;
            groupBoxDESKeys.Location = new Point(9, 10);
            groupBoxDESKeys.Name = "groupBoxDESKeys";
            groupBoxDESKeys.Padding = new Padding(6, 7, 6, 7);
            groupBoxDESKeys.Size = new Size(976, 167);
            groupBoxDESKeys.TabIndex = 0;
            groupBoxDESKeys.TabStop = false;
            groupBoxDESKeys.Text = "DES密钥生成";
            // 
            // tableLayoutDESKeys
            // 
            tableLayoutDESKeys.ColumnCount = 1;
            tableLayoutDESKeys.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            tableLayoutDESKeys.Controls.Add(panelDESKeyControls, 0, 0);
            tableLayoutDESKeys.Controls.Add(labelDESKey, 0, 1);
            tableLayoutDESKeys.Controls.Add(panelDESKey, 0, 2);
            tableLayoutDESKeys.Controls.Add(panelDESIVControls, 0, 3);
            tableLayoutDESKeys.Controls.Add(labelDESIV, 0, 4);
            tableLayoutDESKeys.Controls.Add(panelDESIV, 0, 5);
            tableLayoutDESKeys.Dock = DockStyle.Fill;
            tableLayoutDESKeys.Location = new Point(6, 23);
            tableLayoutDESKeys.Margin = new Padding(2, 3, 2, 3);
            tableLayoutDESKeys.Name = "tableLayoutDESKeys";
            tableLayoutDESKeys.RowCount = 6;
            tableLayoutDESKeys.RowStyles.Add(new RowStyle(SizeType.Absolute, 34F));
            tableLayoutDESKeys.RowStyles.Add(new RowStyle(SizeType.Absolute, 21F));
            tableLayoutDESKeys.RowStyles.Add(new RowStyle(SizeType.Absolute, 30F));
            tableLayoutDESKeys.RowStyles.Add(new RowStyle(SizeType.Absolute, 34F));
            tableLayoutDESKeys.RowStyles.Add(new RowStyle(SizeType.Absolute, 21F));
            tableLayoutDESKeys.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
            tableLayoutDESKeys.Size = new Size(964, 137);
            tableLayoutDESKeys.TabIndex = 0;
            // 
            // panelDESKeyControls
            // 
            panelDESKeyControls.Controls.Add(btnConvertDESKey);
            panelDESKeyControls.Controls.Add(btnGenerateDESKey);
            panelDESKeyControls.Controls.Add(comboDESKeyFormat);
            panelDESKeyControls.Controls.Add(labelDESKeyFormat);
            panelDESKeyControls.Dock = DockStyle.Fill;
            panelDESKeyControls.Location = new Point(2, 3);
            panelDESKeyControls.Margin = new Padding(2, 3, 2, 3);
            panelDESKeyControls.Name = "panelDESKeyControls";
            panelDESKeyControls.Size = new Size(960, 28);
            panelDESKeyControls.TabIndex = 0;
            // 
            // btnConvertDESKey
            // 
            btnConvertDESKey.Location = new Point(171, 2);
            btnConvertDESKey.Name = "btnConvertDESKey";
            btnConvertDESKey.Size = new Size(62, 26);
            btnConvertDESKey.TabIndex = 1;
            btnConvertDESKey.Text = "转换格式";
            btnConvertDESKey.UseVisualStyleBackColor = true;
            btnConvertDESKey.Click += btnConvertDESKey_Click;
            // 
            // btnGenerateDESKey
            // 
            btnGenerateDESKey.Location = new Point(241, 2);
            btnGenerateDESKey.Name = "btnGenerateDESKey";
            btnGenerateDESKey.Size = new Size(80, 26);
            btnGenerateDESKey.TabIndex = 0;
            btnGenerateDESKey.Text = "生成密钥";
            btnGenerateDESKey.UseVisualStyleBackColor = true;
            btnGenerateDESKey.Click += btnGenerateDESKey_Click;
            // 
            // comboDESKeyFormat
            // 
            comboDESKeyFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboDESKeyFormat.FormattingEnabled = true;
            comboDESKeyFormat.Items.AddRange(new object[] { "UTF8", "Base64", "Hex" });
            comboDESKeyFormat.Location = new Point(62, 3);
            comboDESKeyFormat.Name = "comboDESKeyFormat";
            comboDESKeyFormat.Size = new Size(100, 25);
            comboDESKeyFormat.TabIndex = 10;
            // 
            // labelDESKeyFormat
            // 
            labelDESKeyFormat.AutoSize = true;
            labelDESKeyFormat.Location = new Point(0, 7);
            labelDESKeyFormat.Name = "labelDESKeyFormat";
            labelDESKeyFormat.Size = new Size(59, 17);
            labelDESKeyFormat.TabIndex = 11;
            labelDESKeyFormat.Text = "密钥格式:";
            // 
            // labelDESKey
            // 
            labelDESKey.AutoSize = true;
            labelDESKey.Dock = DockStyle.Bottom;
            labelDESKey.Location = new Point(3, 38);
            labelDESKey.Name = "labelDESKey";
            labelDESKey.Size = new Size(958, 17);
            labelDESKey.TabIndex = 3;
            labelDESKey.Text = "DES密钥:";
            // 
            // panelDESKey
            // 
            panelDESKey.Controls.Add(textDESKey);
            panelDESKey.Dock = DockStyle.Fill;
            panelDESKey.Location = new Point(2, 58);
            panelDESKey.Margin = new Padding(2, 3, 2, 3);
            panelDESKey.Name = "panelDESKey";
            panelDESKey.Size = new Size(960, 24);
            panelDESKey.TabIndex = 4;
            // 
            // textDESKey
            // 
            textDESKey.Dock = DockStyle.Fill;
            textDESKey.Location = new Point(0, 0);
            textDESKey.Name = "textDESKey";
            textDESKey.Size = new Size(960, 23);
            textDESKey.TabIndex = 2;
            // 
            // panelDESIVControls
            // 
            panelDESIVControls.Controls.Add(btnConvertDESIV);
            panelDESIVControls.Controls.Add(btnGenerateDESIV);
            panelDESIVControls.Controls.Add(comboDESIVFormat);
            panelDESIVControls.Controls.Add(labelDESIVFormat);
            panelDESIVControls.Dock = DockStyle.Fill;
            panelDESIVControls.Location = new Point(2, 88);
            panelDESIVControls.Margin = new Padding(2, 3, 2, 3);
            panelDESIVControls.Name = "panelDESIVControls";
            panelDESIVControls.Size = new Size(960, 28);
            panelDESIVControls.TabIndex = 1;
            // 
            // btnConvertDESIV
            // 
            btnConvertDESIV.Location = new Point(171, 2);
            btnConvertDESIV.Name = "btnConvertDESIV";
            btnConvertDESIV.Size = new Size(62, 26);
            btnConvertDESIV.TabIndex = 2;
            btnConvertDESIV.Text = "转换格式";
            btnConvertDESIV.UseVisualStyleBackColor = true;
            btnConvertDESIV.Click += btnConvertDESIV_Click;
            // 
            // btnGenerateDESIV
            // 
            btnGenerateDESIV.Location = new Point(241, 2);
            btnGenerateDESIV.Name = "btnGenerateDESIV";
            btnGenerateDESIV.Size = new Size(80, 26);
            btnGenerateDESIV.TabIndex = 1;
            btnGenerateDESIV.Text = "生成向量";
            btnGenerateDESIV.UseVisualStyleBackColor = true;
            btnGenerateDESIV.Click += btnGenerateDESIV_Click;
            // 
            // comboDESIVFormat
            // 
            comboDESIVFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboDESIVFormat.FormattingEnabled = true;
            comboDESIVFormat.Items.AddRange(new object[] { "UTF8", "Base64", "Hex" });
            comboDESIVFormat.Location = new Point(62, 3);
            comboDESIVFormat.Name = "comboDESIVFormat";
            comboDESIVFormat.Size = new Size(100, 25);
            comboDESIVFormat.TabIndex = 10;
            // 
            // labelDESIVFormat
            // 
            labelDESIVFormat.AutoSize = true;
            labelDESIVFormat.Location = new Point(0, 7);
            labelDESIVFormat.Name = "labelDESIVFormat";
            labelDESIVFormat.Size = new Size(59, 17);
            labelDESIVFormat.TabIndex = 11;
            labelDESIVFormat.Text = "向量格式:";
            // 
            // labelDESIV
            // 
            labelDESIV.AutoSize = true;
            labelDESIV.Dock = DockStyle.Bottom;
            labelDESIV.Location = new Point(3, 123);
            labelDESIV.Name = "labelDESIV";
            labelDESIV.Size = new Size(958, 17);
            labelDESIV.TabIndex = 5;
            labelDESIV.Text = "初始向量:";
            // 
            // panelDESIV
            // 
            panelDESIV.Controls.Add(textDESIV);
            panelDESIV.Dock = DockStyle.Fill;
            panelDESIV.Location = new Point(2, 143);
            panelDESIV.Margin = new Padding(2, 3, 2, 3);
            panelDESIV.Name = "panelDESIV";
            panelDESIV.Size = new Size(960, 1);
            panelDESIV.TabIndex = 6;
            // 
            // textDESIV
            // 
            textDESIV.Dock = DockStyle.Fill;
            textDESIV.Location = new Point(0, 0);
            textDESIV.Name = "textDESIV";
            textDESIV.Size = new Size(960, 23);
            textDESIV.TabIndex = 4;
            // 
            // groupBoxDESEncrypt
            // 
            groupBoxDESEncrypt.Controls.Add(tableLayoutDESEncrypt);
            groupBoxDESEncrypt.Dock = DockStyle.Fill;
            groupBoxDESEncrypt.Location = new Point(9, 183);
            groupBoxDESEncrypt.Name = "groupBoxDESEncrypt";
            groupBoxDESEncrypt.Padding = new Padding(6, 7, 6, 7);
            groupBoxDESEncrypt.Size = new Size(976, 317);
            groupBoxDESEncrypt.TabIndex = 1;
            groupBoxDESEncrypt.TabStop = false;
            groupBoxDESEncrypt.Text = "DES加密解密";
            // 
            // tableLayoutDESEncrypt
            // 
            tableLayoutDESEncrypt.ColumnCount = 1;
            tableLayoutDESEncrypt.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            tableLayoutDESEncrypt.Controls.Add(panelDESEncryptControls, 0, 0);
            tableLayoutDESEncrypt.Controls.Add(labelPlaintext, 0, 1);
            tableLayoutDESEncrypt.Controls.Add(textDESPlainText, 0, 2);
            tableLayoutDESEncrypt.Controls.Add(labelCiphertext, 0, 3);
            tableLayoutDESEncrypt.Controls.Add(textDESCipherText, 0, 4);
            tableLayoutDESEncrypt.Dock = DockStyle.Fill;
            tableLayoutDESEncrypt.Location = new Point(6, 23);
            tableLayoutDESEncrypt.Margin = new Padding(2, 3, 2, 3);
            tableLayoutDESEncrypt.Name = "tableLayoutDESEncrypt";
            tableLayoutDESEncrypt.RowCount = 5;
            tableLayoutDESEncrypt.RowStyles.Add(new RowStyle(SizeType.Absolute, 68F));
            tableLayoutDESEncrypt.RowStyles.Add(new RowStyle(SizeType.Absolute, 21F));
            tableLayoutDESEncrypt.RowStyles.Add(new RowStyle(SizeType.Percent, 50F));
            tableLayoutDESEncrypt.RowStyles.Add(new RowStyle(SizeType.Absolute, 21F));
            tableLayoutDESEncrypt.RowStyles.Add(new RowStyle(SizeType.Percent, 50F));
            tableLayoutDESEncrypt.Size = new Size(964, 287);
            tableLayoutDESEncrypt.TabIndex = 0;
            // 
            // panelDESEncryptControls
            // 
            panelDESEncryptControls.Controls.Add(btnDecryptFile);
            panelDESEncryptControls.Controls.Add(btnEncryptFile);
            panelDESEncryptControls.Controls.Add(btnDESDecrypt);
            panelDESEncryptControls.Controls.Add(btnDESEncrypt);
            panelDESEncryptControls.Controls.Add(comboDESCiphertextFormat);
            panelDESEncryptControls.Controls.Add(labelDESCiphertextFormat);
            panelDESEncryptControls.Controls.Add(comboDESPlaintextFormat);
            panelDESEncryptControls.Controls.Add(labelDESPlaintextFormat);
            panelDESEncryptControls.Controls.Add(comboDESPadding);
            panelDESEncryptControls.Controls.Add(labelDESPadding);
            panelDESEncryptControls.Controls.Add(comboDESMode);
            panelDESEncryptControls.Controls.Add(labelDESMode);
            panelDESEncryptControls.Dock = DockStyle.Fill;
            panelDESEncryptControls.Location = new Point(2, 3);
            panelDESEncryptControls.Margin = new Padding(2, 3, 2, 3);
            panelDESEncryptControls.Name = "panelDESEncryptControls";
            panelDESEncryptControls.Size = new Size(960, 62);
            panelDESEncryptControls.TabIndex = 0;
            // 
            // btnDecryptFile
            // 
            btnDecryptFile.Location = new Point(773, 33);
            btnDecryptFile.Name = "btnDecryptFile";
            btnDecryptFile.Size = new Size(74, 26);
            btnDecryptFile.TabIndex = 3;
            btnDecryptFile.Text = "解密文件";
            btnDecryptFile.UseVisualStyleBackColor = true;
            btnDecryptFile.Click += btnDecryptFile_Click;
            // 
            // btnEncryptFile
            // 
            btnEncryptFile.Location = new Point(684, 34);
            btnEncryptFile.Name = "btnEncryptFile";
            btnEncryptFile.Size = new Size(76, 26);
            btnEncryptFile.TabIndex = 2;
            btnEncryptFile.Text = "加密文件";
            btnEncryptFile.UseVisualStyleBackColor = true;
            btnEncryptFile.Click += btnEncryptFile_Click;
            // 
            // btnDESDecrypt
            // 
            btnDESDecrypt.Location = new Point(773, 1);
            btnDESDecrypt.Name = "btnDESDecrypt";
            btnDESDecrypt.Size = new Size(74, 26);
            btnDESDecrypt.TabIndex = 1;
            btnDESDecrypt.Text = "解密";
            btnDESDecrypt.UseVisualStyleBackColor = true;
            btnDESDecrypt.Click += btnDESDecrypt_Click;
            // 
            // btnDESEncrypt
            // 
            btnDESEncrypt.Location = new Point(684, 2);
            btnDESEncrypt.Name = "btnDESEncrypt";
            btnDESEncrypt.Size = new Size(76, 26);
            btnDESEncrypt.TabIndex = 0;
            btnDESEncrypt.Text = "加密";
            btnDESEncrypt.UseVisualStyleBackColor = true;
            btnDESEncrypt.Click += btnDESEncrypt_Click;
            // 
            // comboDESCiphertextFormat
            // 
            comboDESCiphertextFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboDESCiphertextFormat.FormattingEnabled = true;
            comboDESCiphertextFormat.Items.AddRange(new object[] { "Base64", "Hex" });
            comboDESCiphertextFormat.Location = new Point(576, 3);
            comboDESCiphertextFormat.Name = "comboDESCiphertextFormat";
            comboDESCiphertextFormat.Size = new Size(100, 25);
            comboDESCiphertextFormat.TabIndex = 8;
            // 
            // labelDESCiphertextFormat
            // 
            labelDESCiphertextFormat.AutoSize = true;
            labelDESCiphertextFormat.Location = new Point(513, 7);
            labelDESCiphertextFormat.Name = "labelDESCiphertextFormat";
            labelDESCiphertextFormat.Size = new Size(59, 17);
            labelDESCiphertextFormat.TabIndex = 9;
            labelDESCiphertextFormat.Text = "密文格式:";
            // 
            // comboDESPlaintextFormat
            // 
            comboDESPlaintextFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboDESPlaintextFormat.FormattingEnabled = true;
            comboDESPlaintextFormat.Items.AddRange(new object[] { "UTF8", "Base64", "Hex" });
            comboDESPlaintextFormat.Location = new Point(404, 3);
            comboDESPlaintextFormat.Name = "comboDESPlaintextFormat";
            comboDESPlaintextFormat.Size = new Size(100, 25);
            comboDESPlaintextFormat.TabIndex = 10;
            // 
            // labelDESPlaintextFormat
            // 
            labelDESPlaintextFormat.AutoSize = true;
            labelDESPlaintextFormat.Location = new Point(342, 7);
            labelDESPlaintextFormat.Name = "labelDESPlaintextFormat";
            labelDESPlaintextFormat.Size = new Size(59, 17);
            labelDESPlaintextFormat.TabIndex = 11;
            labelDESPlaintextFormat.Text = "明文格式:";
            // 
            // comboDESPadding
            // 
            comboDESPadding.DropDownStyle = ComboBoxStyle.DropDownList;
            comboDESPadding.FormattingEnabled = true;
            comboDESPadding.Items.AddRange(new object[] { "PKCS7", "PKCS5", "Zeros", "ISO10126", "ANSIX923", "None" });
            comboDESPadding.Location = new Point(233, 3);
            comboDESPadding.Name = "comboDESPadding";
            comboDESPadding.Size = new Size(100, 25);
            comboDESPadding.TabIndex = 6;
            // 
            // labelDESPadding
            // 
            labelDESPadding.AutoSize = true;
            labelDESPadding.Location = new Point(171, 7);
            labelDESPadding.Name = "labelDESPadding";
            labelDESPadding.Size = new Size(59, 17);
            labelDESPadding.TabIndex = 7;
            labelDESPadding.Text = "填充模式:";
            // 
            // comboDESMode
            // 
            comboDESMode.DropDownStyle = ComboBoxStyle.DropDownList;
            comboDESMode.FormattingEnabled = true;
            comboDESMode.Items.AddRange(new object[] { "ECB", "CBC", "CFB", "OFB" });
            comboDESMode.Location = new Point(62, 3);
            comboDESMode.Name = "comboDESMode";
            comboDESMode.Size = new Size(100, 25);
            comboDESMode.TabIndex = 4;
            comboDESMode.SelectedIndexChanged += comboDESMode_SelectedIndexChanged;
            // 
            // labelDESMode
            // 
            labelDESMode.AutoSize = true;
            labelDESMode.Location = new Point(0, 7);
            labelDESMode.Name = "labelDESMode";
            labelDESMode.Size = new Size(59, 17);
            labelDESMode.TabIndex = 5;
            labelDESMode.Text = "加密模式:";
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
            // textDESPlainText
            // 
            textDESPlainText.Dock = DockStyle.Fill;
            textDESPlainText.Location = new Point(3, 92);
            textDESPlainText.Multiline = true;
            textDESPlainText.Name = "textDESPlainText";
            textDESPlainText.ScrollBars = ScrollBars.Both;
            textDESPlainText.Size = new Size(958, 82);
            textDESPlainText.TabIndex = 2;
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
            // textDESCipherText
            // 
            textDESCipherText.Dock = DockStyle.Fill;
            textDESCipherText.Location = new Point(3, 201);
            textDESCipherText.Multiline = true;
            textDESCipherText.Name = "textDESCipherText";
            textDESCipherText.ScrollBars = ScrollBars.Both;
            textDESCipherText.Size = new Size(958, 83);
            textDESCipherText.TabIndex = 3;
            // 
            // DESTabControl
            // 
            AutoScaleDimensions = new SizeF(7F, 17F);
            AutoScaleMode = AutoScaleMode.Font;
            Controls.Add(mainTableLayout);
            Name = "DESTabControl";
            Size = new Size(994, 510);
            mainTableLayout.ResumeLayout(false);
            groupBoxDESKeys.ResumeLayout(false);
            tableLayoutDESKeys.ResumeLayout(false);
            tableLayoutDESKeys.PerformLayout();
            panelDESKeyControls.ResumeLayout(false);
            panelDESKeyControls.PerformLayout();
            panelDESKey.ResumeLayout(false);
            panelDESKey.PerformLayout();
            panelDESIVControls.ResumeLayout(false);
            panelDESIVControls.PerformLayout();
            panelDESIV.ResumeLayout(false);
            panelDESIV.PerformLayout();
            groupBoxDESEncrypt.ResumeLayout(false);
            tableLayoutDESEncrypt.ResumeLayout(false);
            tableLayoutDESEncrypt.PerformLayout();
            panelDESEncryptControls.ResumeLayout(false);
            panelDESEncryptControls.PerformLayout();
            ResumeLayout(false);
        }

        #endregion

        private TableLayoutPanel mainTableLayout;
        private GroupBox groupBoxDESKeys;
        private TableLayoutPanel tableLayoutDESKeys;
        private Panel panelDESKeyControls;
        private Label labelDESKeyFormat;
        private ComboBox comboDESKeyFormat;
        private Button btnConvertDESKey;
        private Button btnGenerateDESKey;
        private Label labelDESKey;
        private Panel panelDESKey;
        private TextBox textDESKey;
        private Panel panelDESIVControls;
        private Label labelDESIVFormat;
        private ComboBox comboDESIVFormat;
        private Button btnConvertDESIV;
        private Button btnGenerateDESIV;
        private Label labelDESIV;
        private Panel panelDESIV;
        private TextBox textDESIV;
        private GroupBox groupBoxDESEncrypt;
        private TableLayoutPanel tableLayoutDESEncrypt;
        private Panel panelDESEncryptControls;
        private Button btnDecryptFile;
        private Button btnEncryptFile;
        private Button btnDESDecrypt;
        private Button btnDESEncrypt;
        private ComboBox comboDESCiphertextFormat;
        private Label labelDESCiphertextFormat;
        private ComboBox comboDESPlaintextFormat;
        private Label labelDESPlaintextFormat;
        private ComboBox comboDESPadding;
        private Label labelDESPadding;
        private ComboBox comboDESMode;
        private Label labelDESMode;
        private Label labelPlaintext;
        private TextBox textDESPlainText;
        private Label labelCiphertext;
        private TextBox textDESCipherText;
    }
}
