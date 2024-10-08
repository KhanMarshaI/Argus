using MaterialSkin;
using MaterialSkin.Controls;

namespace Argus
{
    public partial class Form1 : MaterialForm
    {
        public Form1()
        {
            InitializeComponent();

            var materialSkinManager = MaterialSkinManager.Instance;
            materialSkinManager.AddFormToManage(this);
            materialSkinManager.Theme = MaterialSkinManager.Themes.DARK;
            materialSkinManager.ColorScheme = new ColorScheme(Primary.Grey900, Primary.Grey800,
                Primary.Grey500, Accent.Red700, TextShade.WHITE);
        }

        private void materialLabel1_Click(object sender, EventArgs e)
        {

        }
    }
}
