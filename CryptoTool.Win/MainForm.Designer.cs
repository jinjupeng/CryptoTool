namespace CryptoTool.Win
{
    partial class MainForm
    {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            tabControl1 = new TabControl();
            tabRSA = new TabPage();
            tabRSAConvert = new TabPage();
            tabSM4 = new TabPage();
            tabSM2 = new TabPage();
            tabSM3 = new TabPage();
            tabMedicare = new TabPage();
            tabAbout = new TabPage();
            statusStrip1 = new StatusStrip();
            toolStripStatusLabel1 = new ToolStripStatusLabel();
            tabControl1.SuspendLayout();
            statusStrip1.SuspendLayout();
            SuspendLayout();
            // 
            // tabControl1
            // 
            tabControl1.Controls.Add(tabRSA);
            tabControl1.Controls.Add(tabRSAConvert);
            tabControl1.Controls.Add(tabSM4);
            tabControl1.Controls.Add(tabSM2);
            tabControl1.Controls.Add(tabSM3);
            tabControl1.Controls.Add(tabMedicare);
            tabControl1.Controls.Add(tabAbout);
            tabControl1.Dock = DockStyle.Fill;
            tabControl1.Location = new Point(0, 0);
            tabControl1.Margin = new Padding(4);
            tabControl1.Name = "tabControl1";
            tabControl1.SelectedIndex = 0;
            tabControl1.Size = new Size(1286, 1055);
            tabControl1.TabIndex = 0;
            // 
            // tabRSA
            // 
            tabRSA.Location = new Point(4, 29);
            tabRSA.Margin = new Padding(4);
            tabRSA.Name = "tabRSA";
            tabRSA.Padding = new Padding(4);
            tabRSA.Size = new Size(1278, 1022);
            tabRSA.TabIndex = 0;
            tabRSA.Text = "RSA算法";
            tabRSA.UseVisualStyleBackColor = true;
            // 
            // tabRSAConvert
            // 
            tabRSAConvert.Location = new Point(4, 29);
            tabRSAConvert.Margin = new Padding(4);
            tabRSAConvert.Name = "tabRSAConvert";
            tabRSAConvert.Padding = new Padding(4);
            tabRSAConvert.Size = new Size(1278, 1022);
            tabRSAConvert.TabIndex = 5;
            tabRSAConvert.Text = "RSA格式转换";
            tabRSAConvert.UseVisualStyleBackColor = true;
            // 
            // tabSM4
            // 
            tabSM4.Location = new Point(4, 29);
            tabSM4.Margin = new Padding(4);
            tabSM4.Name = "tabSM4";
            tabSM4.Padding = new Padding(4);
            tabSM4.Size = new Size(1278, 1022);
            tabSM4.TabIndex = 1;
            tabSM4.Text = "SM4算法";
            tabSM4.UseVisualStyleBackColor = true;
            // 
            // tabSM2
            // 
            tabSM2.Location = new Point(4, 29);
            tabSM2.Margin = new Padding(4);
            tabSM2.Name = "tabSM2";
            tabSM2.Padding = new Padding(4);
            tabSM2.Size = new Size(1278, 1022);
            tabSM2.TabIndex = 2;
            tabSM2.Text = "SM2算法";
            tabSM2.UseVisualStyleBackColor = true;
            // 
            // tabSM3
            // 
            tabSM3.Location = new Point(4, 29);
            tabSM3.Margin = new Padding(4);
            tabSM3.Name = "tabSM3";
            tabSM3.Padding = new Padding(4);
            tabSM3.Size = new Size(1278, 1022);
            tabSM3.TabIndex = 3;
            tabSM3.Text = "SM3算法";
            tabSM3.UseVisualStyleBackColor = true;
            // 
            // tabMedicare
            // 
            tabMedicare.Location = new Point(4, 29);
            tabMedicare.Margin = new Padding(4);
            tabMedicare.Name = "tabMedicare";
            tabMedicare.Padding = new Padding(3, 4, 3, 4);
            tabMedicare.Size = new Size(1278, 1022);
            tabMedicare.TabIndex = 4;
            tabMedicare.Text = "医保接口";
            tabMedicare.UseVisualStyleBackColor = true;
            // 
            // tabAbout
            // 
            tabAbout.Location = new Point(4, 29);
            tabAbout.Margin = new Padding(4);
            tabAbout.Name = "tabAbout";
            tabAbout.Padding = new Padding(3, 4, 3, 4);
            tabAbout.Size = new Size(1278, 1022);
            tabAbout.TabIndex = 6;
            tabAbout.Text = "关于";
            tabAbout.UseVisualStyleBackColor = true;
            // 
            // statusStrip1
            // 
            statusStrip1.ImageScalingSize = new Size(20, 20);
            statusStrip1.Items.AddRange(new ToolStripItem[] { toolStripStatusLabel1 });
            statusStrip1.Location = new Point(0, 1029);
            statusStrip1.Name = "statusStrip1";
            statusStrip1.Padding = new Padding(1, 0, 18, 0);
            statusStrip1.Size = new Size(1286, 26);
            statusStrip1.TabIndex = 1;
            statusStrip1.Text = "statusStrip1";
            // 
            // toolStripStatusLabel1
            // 
            toolStripStatusLabel1.Name = "toolStripStatusLabel1";
            toolStripStatusLabel1.Size = new Size(39, 20);
            toolStripStatusLabel1.Text = "就绪";
            // 
            // MainForm
            // 
            AutoScaleDimensions = new SizeF(9F, 20F);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(1286, 1055);
            Controls.Add(statusStrip1);
            Controls.Add(tabControl1);
            Margin = new Padding(4);
            Name = "MainForm";
            StartPosition = FormStartPosition.CenterScreen;
            Text = "加解密工具";
            Load += Form1_Load;
            tabControl1.ResumeLayout(false);
            statusStrip1.ResumeLayout(false);
            statusStrip1.PerformLayout();
            ResumeLayout(false);
            PerformLayout();
        }

        #endregion

        private System.Windows.Forms.TabControl tabControl1;
        private System.Windows.Forms.TabPage tabRSA;
        private System.Windows.Forms.TabPage tabRSAConvert;
        private System.Windows.Forms.TabPage tabSM4;
        private System.Windows.Forms.TabPage tabSM2;
        private TabPage tabSM3;
        private TabPage tabMedicare;
        private TabPage tabAbout;
        private StatusStrip statusStrip1;
        private ToolStripStatusLabel toolStripStatusLabel1;
    }

    /// <summary>
    /// 定义一个表示下拉选项的类
    /// </summary>
    public class ComboBoxItem
    {
        public string Text { get; set; }  // 显示的文字
        public object Value { get; set; } // 关联的值，使用 object 类型更通用

        // 可选：重写 ToString 方法，通常绑定后不需要，但有时可备用
        public override string ToString()
        {
            return Text;
        }
    }
}
