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
using BCrypt.Net;
using identityValidator;
using System.Linq.Expressions;

namespace identityValidator
{
    public class identityHelper
    {
        public static bool passwordVerify(string password, string hashedPass) 
        //static are shared across all instances. class-level method. Could be called without creating an object first.
        {
            if (hashedPass == null) return false;
            return BCrypt.Net.BCrypt.Verify(password, hashedPass);
        }

        private static string envPass = Environment.GetEnvironmentVariable("DB_PASSWORD");
        private static string connectionString = "Server=tcp:marshal.database.windows.net,1433;Initial Catalog=argus;" +
            $"Persist Security Info=False;User ID=marshal;Password={envPass};MultipleActiveResultSets=False;Encrypt=True;" +
            "TrustServerCertificate=False;Connection Timeout=30;";

        private static Dictionary<string, string> passCache = new Dictionary<string, string>();

        public static async Task<string> retrieveDBPass(string username)
        {

            if(passCache.TryGetValue(username, out string cachedHashPass))
            {
                return cachedHashPass;
            }

            string hashedPassword = null;
            string query = "SELECT password FROM authorized_users WHERE username = @username";

            using (SqlConnection con = new SqlConnection(connectionString))
            {
                try
                {
                    await con.OpenAsync();
                    using (SqlCommand cmd = new SqlCommand(query, con))
                    {
                        cmd.Parameters.AddWithValue("@username", username);
                        var result = await cmd.ExecuteScalarAsync(); //compiler infers the data type
                        if (result != null)
                        {
                            hashedPassword = result.ToString();
                            passCache[username] = hashedPassword;
                        }
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"An error occured. {ex.Message}", "Fail", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                con.Close();
            }
            return hashedPassword;
        }
    }
}

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

        private static Dictionary<string, DateTime> loginAttempts = new Dictionary<string, DateTime>();
        private static TimeSpan cooldown = TimeSpan.FromSeconds(30);

        private async void Button_Click_1(object sender, RoutedEventArgs e)
        {
            string username = usernameBox.Text.ToString();
            string password = passwordBox.Password;

            if (string.IsNullOrEmpty(username)|| string.IsNullOrEmpty(password))
            {
                MessageBox.Show("Enter credentials", "Fail", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            if(loginAttempts.TryGetValue(username, out DateTime lastAttempt) && DateTime.Now - lastAttempt < cooldown)
            {
                MessageBox.Show("Too many incorrect login attempts were made.", "Wait", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            loginAttempts[username] = DateTime.Now;
            string dbPassword = await identityHelper.retrieveDBPass(username);
            bool isPassValid = await Task.Run(() => identityHelper.passwordVerify(password, dbPassword));

            if (isPassValid)
            {
                MessageBox.Show("Login Successful.", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                loginAttempts.Remove(username);
            }
            else MessageBox.Show("Incorrect Credentials.", "Fail", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}
