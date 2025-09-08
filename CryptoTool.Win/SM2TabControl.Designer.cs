namespace CryptoTool.Win
{
    partial class SM2TabControl : UserControl
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
            groupBoxSM2Sign = new GroupBox();
            labelSM2VerifyResult = new Label();
            label24 = new Label();
            textSM2Signature = new TextBox();
            label23 = new Label();
            textSM2SignData = new TextBox();
            btnSM2Verify = new Button();
            btnSM2Sign = new Button();
            label22 = new Label();
            comboSM2SignFormat = new ComboBox();
            groupBoxSM2Encrypt = new GroupBox();
            label21 = new Label();
            textSM2CipherText = new TextBox();
            label20 = new Label();
            textSM2PlainText = new TextBox();
            btnSM2Decrypt = new Button();
            btnSM2Encrypt = new Button();
            label19 = new Label();
            comboSM2CipherFormat = new ComboBox();
            groupBoxSM2Keys = new GroupBox();
            btnExportSM2Key = new Button();
            btnImportSM2Key = new Button();
            label18 = new Label();
            textSM2PrivateKey = new TextBox();
            label17 = new Label();
            textSM2PublicKey = new TextBox();
            label16 = new Label();
            comboSM2KeyFormat = new ComboBox();
            btnGenerateSM2Key = new Button();
            groupBoxSM2Sign.SuspendLayout();
            groupBoxSM2Encrypt.SuspendLayout();
            groupBoxSM2Keys.SuspendLayout();
            SuspendLayout();
            // 
            // groupBoxSM2Sign
            // 
            groupBoxSM2Sign.Controls.Add(labelSM2VerifyResult);
            groupBoxSM2Sign.Controls.Add(label24);
            groupBoxSM2Sign.Controls.Add(textSM2Signature);
            groupBoxSM2Sign.Controls.Add(label23);
            groupBoxSM2Sign.Controls.Add(textSM2SignData);
            groupBoxSM2Sign.Controls.Add(btnSM2Verify);
            groupBoxSM2Sign.Controls.Add(btnSM2Sign);
            groupBoxSM2Sign.Controls.Add(label22);
            groupBoxSM2Sign.Controls.Add(comboSM2SignFormat);
            groupBoxSM2Sign.Location = new Point(8, 468);
            groupBoxSM2Sign.Margin = new Padding(4);
            groupBoxSM2Sign.Name = "groupBoxSM2Sign";
            groupBoxSM2Sign.Padding = new Padding(4);
            groupBoxSM2Sign.Size = new Size(1260, 375);
            groupBoxSM2Sign.TabIndex = 2;
            groupBoxSM2Sign.TabStop = false;
            groupBoxSM2Sign.Text = "SM2数字签名";
            // 
            // labelSM2VerifyResult
            // 
            labelSM2VerifyResult.AutoSize = true;
            labelSM2VerifyResult.Location = new Point(514, 302);
            labelSM2VerifyResult.Margin = new Padding(4, 0, 4, 0);
            labelSM2VerifyResult.Name = "labelSM2VerifyResult";
            labelSM2VerifyResult.Size = new Size(73, 20);
            labelSM2VerifyResult.TabIndex = 8;
            labelSM2VerifyResult.Text = "验签结果:";
            // 
            // label24
            // 
            label24.AutoSize = true;
            label24.Location = new Point(19, 224);
            label24.Margin = new Padding(4, 0, 4, 0);
            label24.Name = "label24";
            label24.Size = new Size(43, 20);
            label24.TabIndex = 7;
            label24.Text = "签名:";
            // 
            // textSM2Signature
            // 
            textSM2Signature.Location = new Point(103, 220);
            textSM2Signature.Margin = new Padding(4);
            textSM2Signature.Multiline = true;
            textSM2Signature.Name = "textSM2Signature";
            textSM2Signature.ScrollBars = ScrollBars.Both;
            textSM2Signature.Size = new Size(1137, 58);
            textSM2Signature.TabIndex = 6;
            // 
            // label23
            // 
            label23.AutoSize = true;
            label23.Location = new Point(19, 74);
            label23.Margin = new Padding(4, 0, 4, 0);
            label23.Name = "label23";
            label23.Size = new Size(73, 20);
            label23.TabIndex = 5;
            label23.Text = "原文数据:";
            // 
            // textSM2SignData
            // 
            textSM2SignData.Location = new Point(103, 71);
            textSM2SignData.Margin = new Padding(4);
            textSM2SignData.Multiline = true;
            textSM2SignData.Name = "textSM2SignData";
            textSM2SignData.ScrollBars = ScrollBars.Both;
            textSM2SignData.Size = new Size(1137, 130);
            textSM2SignData.TabIndex = 4;
            // 
            // btnSM2Verify
            // 
            btnSM2Verify.Location = new Point(514, 29);
            btnSM2Verify.Margin = new Padding(4);
            btnSM2Verify.Name = "btnSM2Verify";
            btnSM2Verify.Size = new Size(103, 28);
            btnSM2Verify.TabIndex = 3;
            btnSM2Verify.Text = "验签";
            btnSM2Verify.UseVisualStyleBackColor = true;
            btnSM2Verify.Click += btnSM2Verify_Click;
            // 
            // btnSM2Sign
            // 
            btnSM2Sign.Location = new Point(360, 29);
            btnSM2Sign.Margin = new Padding(4);
            btnSM2Sign.Name = "btnSM2Sign";
            btnSM2Sign.Size = new Size(103, 28);
            btnSM2Sign.TabIndex = 2;
            btnSM2Sign.Text = "签名";
            btnSM2Sign.UseVisualStyleBackColor = true;
            btnSM2Sign.Click += btnSM2Sign_Click;
            // 
            // label22
            // 
            label22.AutoSize = true;
            label22.Location = new Point(19, 33);
            label22.Margin = new Padding(4, 0, 4, 0);
            label22.Name = "label22";
            label22.Size = new Size(73, 20);
            label22.TabIndex = 1;
            label22.Text = "签名格式:";
            // 
            // comboSM2SignFormat
            // 
            comboSM2SignFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboSM2SignFormat.FormattingEnabled = true;
            comboSM2SignFormat.Items.AddRange(new object[] { "ASN1", "RS" });
            comboSM2SignFormat.Location = new Point(103, 29);
            comboSM2SignFormat.Margin = new Padding(4);
            comboSM2SignFormat.Name = "comboSM2SignFormat";
            comboSM2SignFormat.Size = new Size(127, 28);
            comboSM2SignFormat.TabIndex = 0;
            // 
            // groupBoxSM2Encrypt
            // 
            groupBoxSM2Encrypt.Controls.Add(label21);
            groupBoxSM2Encrypt.Controls.Add(textSM2CipherText);
            groupBoxSM2Encrypt.Controls.Add(label20);
            groupBoxSM2Encrypt.Controls.Add(textSM2PlainText);
            groupBoxSM2Encrypt.Controls.Add(btnSM2Decrypt);
            groupBoxSM2Encrypt.Controls.Add(btnSM2Encrypt);
            groupBoxSM2Encrypt.Controls.Add(label19);
            groupBoxSM2Encrypt.Controls.Add(comboSM2CipherFormat);
            groupBoxSM2Encrypt.Location = new Point(8, 249);
            groupBoxSM2Encrypt.Margin = new Padding(4);
            groupBoxSM2Encrypt.Name = "groupBoxSM2Encrypt";
            groupBoxSM2Encrypt.Padding = new Padding(4);
            groupBoxSM2Encrypt.Size = new Size(1260, 212);
            groupBoxSM2Encrypt.TabIndex = 1;
            groupBoxSM2Encrypt.TabStop = false;
            groupBoxSM2Encrypt.Text = "SM2加密解密";
            // 
            // label21
            // 
            label21.AutoSize = true;
            label21.Location = new Point(19, 127);
            label21.Margin = new Padding(4, 0, 4, 0);
            label21.Name = "label21";
            label21.Size = new Size(43, 20);
            label21.TabIndex = 7;
            label21.Text = "密文:";
            // 
            // textSM2CipherText
            // 
            textSM2CipherText.Location = new Point(103, 124);
            textSM2CipherText.Margin = new Padding(4);
            textSM2CipherText.Multiline = true;
            textSM2CipherText.Name = "textSM2CipherText";
            textSM2CipherText.ScrollBars = ScrollBars.Both;
            textSM2CipherText.Size = new Size(1137, 80);
            textSM2CipherText.TabIndex = 6;
            // 
            // label20
            // 
            label20.AutoSize = true;
            label20.Location = new Point(19, 74);
            label20.Margin = new Padding(4, 0, 4, 0);
            label20.Name = "label20";
            label20.Size = new Size(43, 20);
            label20.TabIndex = 5;
            label20.Text = "明文:";
            // 
            // textSM2PlainText
            // 
            textSM2PlainText.Location = new Point(103, 71);
            textSM2PlainText.Margin = new Padding(4);
            textSM2PlainText.Multiline = true;
            textSM2PlainText.Name = "textSM2PlainText";
            textSM2PlainText.ScrollBars = ScrollBars.Both;
            textSM2PlainText.Size = new Size(1137, 40);
            textSM2PlainText.TabIndex = 4;
            // 
            // btnSM2Decrypt
            // 
            btnSM2Decrypt.Location = new Point(514, 29);
            btnSM2Decrypt.Margin = new Padding(4);
            btnSM2Decrypt.Name = "btnSM2Decrypt";
            btnSM2Decrypt.Size = new Size(103, 28);
            btnSM2Decrypt.TabIndex = 3;
            btnSM2Decrypt.Text = "解密";
            btnSM2Decrypt.UseVisualStyleBackColor = true;
            btnSM2Decrypt.Click += btnSM2Decrypt_Click;
            // 
            // btnSM2Encrypt
            // 
            btnSM2Encrypt.Location = new Point(360, 29);
            btnSM2Encrypt.Margin = new Padding(4);
            btnSM2Encrypt.Name = "btnSM2Encrypt";
            btnSM2Encrypt.Size = new Size(103, 28);
            btnSM2Encrypt.TabIndex = 2;
            btnSM2Encrypt.Text = "加密";
            btnSM2Encrypt.UseVisualStyleBackColor = true;
            btnSM2Encrypt.Click += btnSM2Encrypt_Click;
            // 
            // label19
            // 
            label19.AutoSize = true;
            label19.Location = new Point(19, 33);
            label19.Margin = new Padding(4, 0, 4, 0);
            label19.Name = "label19";
            label19.Size = new Size(73, 20);
            label19.TabIndex = 1;
            label19.Text = "密文格式:";
            // 
            // comboSM2CipherFormat
            // 
            comboSM2CipherFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboSM2CipherFormat.FormattingEnabled = true;
            comboSM2CipherFormat.Items.AddRange(new object[] { "C1C3C2", "C1C2C3", "ASN1" });
            comboSM2CipherFormat.Location = new Point(103, 29);
            comboSM2CipherFormat.Margin = new Padding(4);
            comboSM2CipherFormat.Name = "comboSM2CipherFormat";
            comboSM2CipherFormat.Size = new Size(127, 28);
            comboSM2CipherFormat.TabIndex = 0;
            // 
            // groupBoxSM2Keys
            // 
            groupBoxSM2Keys.Controls.Add(btnExportSM2Key);
            groupBoxSM2Keys.Controls.Add(btnImportSM2Key);
            groupBoxSM2Keys.Controls.Add(label18);
            groupBoxSM2Keys.Controls.Add(textSM2PrivateKey);
            groupBoxSM2Keys.Controls.Add(label17);
            groupBoxSM2Keys.Controls.Add(textSM2PublicKey);
            groupBoxSM2Keys.Controls.Add(label16);
            groupBoxSM2Keys.Controls.Add(comboSM2KeyFormat);
            groupBoxSM2Keys.Controls.Add(btnGenerateSM2Key);
            groupBoxSM2Keys.Location = new Point(8, 7);
            groupBoxSM2Keys.Margin = new Padding(4);
            groupBoxSM2Keys.Name = "groupBoxSM2Keys";
            groupBoxSM2Keys.Padding = new Padding(4);
            groupBoxSM2Keys.Size = new Size(1260, 235);
            groupBoxSM2Keys.TabIndex = 0;
            groupBoxSM2Keys.TabStop = false;
            groupBoxSM2Keys.Text = "SM2密钥生成";
            // 
            // btnExportSM2Key
            // 
            btnExportSM2Key.Location = new Point(643, 29);
            btnExportSM2Key.Margin = new Padding(4);
            btnExportSM2Key.Name = "btnExportSM2Key";
            btnExportSM2Key.Size = new Size(103, 28);
            btnExportSM2Key.TabIndex = 8;
            btnExportSM2Key.Text = "导出密钥";
            btnExportSM2Key.UseVisualStyleBackColor = true;
            btnExportSM2Key.Click += btnExportSM2Key_Click;
            // 
            // btnImportSM2Key
            // 
            btnImportSM2Key.Location = new Point(514, 29);
            btnImportSM2Key.Margin = new Padding(4);
            btnImportSM2Key.Name = "btnImportSM2Key";
            btnImportSM2Key.Size = new Size(103, 28);
            btnImportSM2Key.TabIndex = 7;
            btnImportSM2Key.Text = "导入密钥";
            btnImportSM2Key.UseVisualStyleBackColor = true;
            btnImportSM2Key.Click += btnImportSM2Key_Click;
            // 
            // label18
            // 
            label18.AutoSize = true;
            label18.Location = new Point(19, 162);
            label18.Margin = new Padding(4, 0, 4, 0);
            label18.Name = "label18";
            label18.Size = new Size(43, 20);
            label18.TabIndex = 6;
            label18.Text = "私钥:";
            // 
            // textSM2PrivateKey
            // 
            textSM2PrivateKey.Location = new Point(103, 159);
            textSM2PrivateKey.Margin = new Padding(4);
            textSM2PrivateKey.Multiline = true;
            textSM2PrivateKey.Name = "textSM2PrivateKey";
            textSM2PrivateKey.ScrollBars = ScrollBars.Both;
            textSM2PrivateKey.Size = new Size(1137, 70);
            textSM2PrivateKey.TabIndex = 5;
            // 
            // label17
            // 
            label17.AutoSize = true;
            label17.Location = new Point(19, 80);
            label17.Margin = new Padding(4, 0, 4, 0);
            label17.Name = "label17";
            label17.Size = new Size(43, 20);
            label17.TabIndex = 4;
            label17.Text = "公钥:";
            // 
            // textSM2PublicKey
            // 
            textSM2PublicKey.Location = new Point(103, 76);
            textSM2PublicKey.Margin = new Padding(4);
            textSM2PublicKey.Multiline = true;
            textSM2PublicKey.Name = "textSM2PublicKey";
            textSM2PublicKey.ScrollBars = ScrollBars.Both;
            textSM2PublicKey.Size = new Size(1137, 70);
            textSM2PublicKey.TabIndex = 3;
            // 
            // label16
            // 
            label16.AutoSize = true;
            label16.Location = new Point(19, 33);
            label16.Margin = new Padding(4, 0, 4, 0);
            label16.Name = "label16";
            label16.Size = new Size(73, 20);
            label16.TabIndex = 2;
            label16.Text = "密钥格式:";
            // 
            // comboSM2KeyFormat
            // 
            comboSM2KeyFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboSM2KeyFormat.FormattingEnabled = true;
            comboSM2KeyFormat.Items.AddRange(new object[] { "Base64", "Hex" });
            comboSM2KeyFormat.Location = new Point(103, 29);
            comboSM2KeyFormat.Margin = new Padding(4);
            comboSM2KeyFormat.Name = "comboSM2KeyFormat";
            comboSM2KeyFormat.Size = new Size(127, 28);
            comboSM2KeyFormat.TabIndex = 1;
            // 
            // btnGenerateSM2Key
            // 
            btnGenerateSM2Key.Location = new Point(360, 29);
            btnGenerateSM2Key.Margin = new Padding(4);
            btnGenerateSM2Key.Name = "btnGenerateSM2Key";
            btnGenerateSM2Key.Size = new Size(129, 28);
            btnGenerateSM2Key.TabIndex = 0;
            btnGenerateSM2Key.Text = "生成密钥对";
            btnGenerateSM2Key.UseVisualStyleBackColor = true;
            btnGenerateSM2Key.Click += btnGenerateSM2Key_Click;
            // 
            // SM2TabControl
            // 
            AutoScaleDimensions = new SizeF(9F, 20F);
            AutoScaleMode = AutoScaleMode.Font;
            Controls.Add(groupBoxSM2Sign);
            Controls.Add(groupBoxSM2Encrypt);
            Controls.Add(groupBoxSM2Keys);
            Margin = new Padding(4);
            Name = "SM2TabControl";
            Size = new Size(1278, 850);
            groupBoxSM2Sign.ResumeLayout(false);
            groupBoxSM2Sign.PerformLayout();
            groupBoxSM2Encrypt.ResumeLayout(false);
            groupBoxSM2Encrypt.PerformLayout();
            groupBoxSM2Keys.ResumeLayout(false);
            groupBoxSM2Keys.PerformLayout();
            ResumeLayout(false);
        }

        #endregion

        private GroupBox groupBoxSM2Sign;
        private Label labelSM2VerifyResult;
        private Label label24;
        private TextBox textSM2Signature;
        private Label label23;
        private TextBox textSM2SignData;
        private Button btnSM2Verify;
        private Button btnSM2Sign;
        private Label label22;
        private ComboBox comboSM2SignFormat;
        private GroupBox groupBoxSM2Encrypt;
        private Label label21;
        private TextBox textSM2CipherText;
        private Label label20;
        private TextBox textSM2PlainText;
        private Button btnSM2Decrypt;
        private Button btnSM2Encrypt;
        private Label label19;
        private ComboBox comboSM2CipherFormat;
        private GroupBox groupBoxSM2Keys;
        private Button btnExportSM2Key;
        private Button btnImportSM2Key;
        private Label label18;
        private TextBox textSM2PrivateKey;
        private Label label17;
        private TextBox textSM2PublicKey;
        private Label label16;
        private ComboBox comboSM2KeyFormat;
        private Button btnGenerateSM2Key;
    }
}