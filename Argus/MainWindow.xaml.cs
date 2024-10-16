using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Data.SqlClient;

namespace Argus
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private bool ValidLogin(string username, string password)
        {
            string connection = "Server=MARSHAL;Database=argus;Trusted_Connection=yes";
            string query = "SELECT COUNT(1) FROM authorized_users WHERE username = @Username " +
                "AND password = @Password";

            using (SqlConnection con = new SqlConnection(connection))
            {
                try
                {
                    con.Open();
                    using(SqlCommand command = new SqlCommand(query, con))
                    {
                        command.Parameters.AddWithValue("@Username", username);
                        command.Parameters.AddWithValue("@Password", password);

                        int result = (int)command.ExecuteScalar();
                        return result == 1;
                    }
                }
                catch (Exception Ex)
                {
                    MessageBox.Show($"An error occured: {Ex.Message}", "Error",MessageBoxButton.OK,MessageBoxImage.Error);
                    return false;
                }
            }
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            string username = usernameBox.Text.ToString();
            string password = passwordBox.Password;

            if (ValidLogin(username, password))
            {
                MessageBox.Show("Login Successful.", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else MessageBox.Show("Login failed.", "Fail", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }
}
