using CryptoTool.Common;
using CryptoTool.Common.GM;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using System.Collections.Generic;
using Newtonsoft.Json;

namespace CryptoTool.Win
{
    public partial class MainForm : Form
    {
        private RSATabControl rsaTabControl;
        private RSAConvertTabControl rsaConvertTabControl;
        private SM4TabControl sm4TabControl;
        private SM2TabControl sm2TabControl;
        private SM3TabControl sm3TabControl;
        private MedicareTabControl medicareTabControl;

        public MainForm()
        {
            InitializeComponent();

            // 设置窗口可调整大小
            this.WindowState = FormWindowState.Maximized;
            this.MinimumSize = new Size(1400, 800);

            InitializeTabControls();
        }

        private void InitializeTabControls()
        {
            // 创建各个用户控件
            rsaTabControl = new RSATabControl();
            rsaConvertTabControl = new RSAConvertTabControl();
            sm4TabControl = new SM4TabControl();
            sm2TabControl = new SM2TabControl();
            sm3TabControl = new SM3TabControl();
            medicareTabControl = new MedicareTabControl();

            // 设置控件尺寸和位置
            rsaTabControl.Dock = DockStyle.Fill;
            rsaConvertTabControl.Dock = DockStyle.Fill;
            sm4TabControl.Dock = DockStyle.Fill;
            sm2TabControl.Dock = DockStyle.Fill;
            sm3TabControl.Dock = DockStyle.Fill;
            medicareTabControl.Dock = DockStyle.Fill;

            // 将控件添加到对应的TabPage中
            tabRSA.Controls.Clear();
            tabRSA.Controls.Add(rsaTabControl);

            tabRSAConvert.Controls.Clear();
            tabRSAConvert.Controls.Add(rsaConvertTabControl);

            tabSM4.Controls.Clear();
            tabSM4.Controls.Add(sm4TabControl);

            tabSM2.Controls.Clear();
            tabSM2.Controls.Add(sm2TabControl);

            tabSM3.Controls.Clear();
            tabSM3.Controls.Add(sm3TabControl);

            tabMedicare.Controls.Clear();
            tabMedicare.Controls.Add(medicareTabControl);

            // 绑定状态更新事件
            rsaTabControl.StatusChanged += SetStatus;
            rsaConvertTabControl.StatusChanged += SetStatus;
            sm4TabControl.StatusChanged += SetStatus;
            sm2TabControl.StatusChanged += SetStatus;
            sm3TabControl.StatusChanged += SetStatus;
            medicareTabControl.StatusChanged += SetStatus;

            // 绑定医保SM4密钥生成事件到SM4控件
            medicareTabControl.SM4KeyGenerated += (key) => sm4TabControl.UpdateKeyFromMedicare(key);
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            SetStatus("就绪");
        }

        #region 辅助方法

        private void SetStatus(string message)
        {
            toolStripStatusLabel1.Text = message;
            Application.DoEvents();
        }

        #endregion
    }
}
