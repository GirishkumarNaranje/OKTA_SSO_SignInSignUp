using OKTA_SSO_SignInSignUp.Models;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data.SqlClient;
using System.Linq;
using System.Web;

namespace OKTA_SSO_SignInSignUp.DBHelper
{
    public class DbHelper
    {
        private string connStr = ConfigurationManager.ConnectionStrings["DefaultConnection"].ConnectionString;

        public void RegisterUser(User user)
        {
            using (SqlConnection conn = new SqlConnection(connStr))
            {
                string query = "INSERT INTO App_User (FirstName, LastName, Username, Email, Password, CreatedDate, Role) VALUES (@FirstName, @LastName, @Username, @Email, @Password, GetDate(), 'Student')";
                SqlCommand cmd = new SqlCommand(query, conn);

                cmd.Parameters.AddWithValue("@FirstName", user.FirstName);
                cmd.Parameters.AddWithValue("@LastName", user.LastName);
                cmd.Parameters.AddWithValue("@Username", user.Username);
                cmd.Parameters.AddWithValue("@Email", user.Email);
                cmd.Parameters.AddWithValue("@Password", user.Password);

                conn.Open();
                cmd.ExecuteNonQuery();
            }
        }

        public User GetUserById(int id)
        {
            using (var conn = new SqlConnection(connStr))
            using (var cmd = new SqlCommand(@"
                SELECT Id, FirstName, LastName, Username, Email, Password, Role, CreatedDate
                FROM App_User WHERE Id = @id", conn))
            {
                cmd.Parameters.AddWithValue("@id", id);
                conn.Open();
                using (var r = cmd.ExecuteReader())
                {
                    if (r.Read())
                    {
                        return new User
                        {
                            Id = (int)r["Id"],
                            FirstName = r["FirstName"] as string,
                            LastName = r["LastName"] as string,
                            Username = r["Username"] as string,
                            Email = r["Email"] as string,
                            Password = r["Password"] as string,  // NOTE: consider masked in UI
                            Role = (r["Role"] as string) ?? "",
                            CreatedDate = r["CreatedDate"] as DateTime?
                        };
                    }
                }
            }
            return null;
        }

        public void EditUser(User user)
        {
            using (var conn = new SqlConnection(connStr))
            using (var cmd = new SqlCommand(@"
                UPDATE App_User
                SET FirstName = @FirstName,
                    LastName  = @LastName,
                    Username  = @Username,
                    Email     = @Email,
                    Role      = @Role
                WHERE Id = @Id", conn))
            {
                cmd.Parameters.AddWithValue("@FirstName", (object)user.FirstName ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@LastName", (object)user.LastName ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@Username", user.Username);
                cmd.Parameters.AddWithValue("@Email", (object)user.Email ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@Role", (object)(user.Role ?? "").Trim());
                cmd.Parameters.AddWithValue("@Id", user.Id);

                conn.Open();
                cmd.ExecuteNonQuery();
            }
        }

        public void DeleteUser(int id)
        {
            using (var conn = new SqlConnection(connStr))
            using (var cmd = new SqlCommand("DELETE FROM App_User WHERE Id = @Id", conn))
            {
                cmd.Parameters.AddWithValue("@Id", id);
                conn.Open();
                cmd.ExecuteNonQuery();
            }
        }



        public User Login(string username, string password)
        {
            using (SqlConnection conn = new SqlConnection(connStr))
            {
                string query = "SELECT * FROM App_User WHERE Username=@Username AND Password=@Password";
                SqlCommand cmd = new SqlCommand(query, conn);

                cmd.Parameters.AddWithValue("@Username", username);
                cmd.Parameters.AddWithValue("@Password", password);

                conn.Open();
                SqlDataReader reader = cmd.ExecuteReader();

                if (reader.Read())
                {
                    return new User
                    {
                        Id = Convert.ToInt32(reader["Id"]),
                        FirstName = reader["FirstName"].ToString(),
                        LastName = reader["LastName"].ToString(),
                        Username = reader["Username"].ToString(),
                        Email = reader["Email"].ToString(),
                        Role = reader["Role"].ToString()
                    };
                }
            }
            return null;
        }

        public List<User> GetAllUsers()
        {
            var list = new List<User>();

            using (var conn = new SqlConnection(connStr))
            using (var cmd = new SqlCommand(@"
                SELECT Id, FirstName, LastName, Username, Email, Role, CreatedDate
                FROM App_User
                ORDER BY CreatedDate DESC", conn))
            {
                conn.Open();
                using (var r = cmd.ExecuteReader())
                {
                    while (r.Read())
                    {
                        list.Add(new User
                        {
                            Id = r.GetInt32(r.GetOrdinal("Id")),
                            FirstName = r["FirstName"] as string,
                            LastName = r["LastName"] as string,
                            Username = r["Username"] as string,
                            Email = r["Email"] as string,
                            Role = r["Role"] as string,
                            CreatedDate = r["CreatedDate"] as System.DateTime? // nullable if column allows nulls
                        });
                    }
                }
            }
            return list;
        }

        public List<Course> GetAllCourses()
        {
            var list = new List<Course>();

            using (var conn = new SqlConnection(connStr))
            using (var cmd = new SqlCommand(@"
                SELECT Id, Name, Totalmarks, IsDeleted, CreatedDate
                FROM Course
                ORDER BY CreatedDate DESC", conn))
            {
                conn.Open();
                using (var r = cmd.ExecuteReader())
                {
                    while (r.Read())
                    {
                        list.Add(new Course
                        {
                            Id = r.GetInt32(r.GetOrdinal("Id")),
                            Name = r["Name"] as string,
                            Totalmarks = r["Totalmarks"] as Int32?,
                            IsDeleted = r["IsDeleted"] as bool?,
                            CreatedDate = r["CreatedDate"] as System.DateTime? 
                        });
                    }
                }
            }
            return list;
        }

        /// <summary>
        /// Get user by email (for Okta SSO users)
        /// </summary>
        public User GetUserByEmail(string email)
        {
            using (SqlConnection conn = new SqlConnection(connStr))
            {
                string query = "SELECT * FROM App_User WHERE Email = @Email";
                SqlCommand cmd = new SqlCommand(query, conn);
                cmd.Parameters.AddWithValue("@Email", email);

                conn.Open();
                SqlDataReader reader = cmd.ExecuteReader();

                if (reader.Read())
                {
                    return new User
                    {
                        Id = Convert.ToInt32(reader["Id"]),
                        FirstName = reader["FirstName"].ToString(),
                        LastName = reader["LastName"].ToString(),
                        Username = reader["Username"].ToString(),
                        Email = reader["Email"].ToString(),
                        Role = reader["Role"].ToString(),
                        CreatedDate = reader["CreatedDate"] as DateTime?
                    };
                }
            }
            return null;
        }

        /// <summary>
        /// Register Okta user (without password)
        /// </summary>
        public void RegisterOktaUser(User user)
        {
            using (SqlConnection conn = new SqlConnection(connStr))
            {
                string query = @"INSERT INTO App_User 
            (FirstName, LastName, Username, Email, Password, CreatedDate, Role) 
            VALUES (@FirstName, @LastName, @Username, @Email, NULL, GETDATE(), @Role)";

                SqlCommand cmd = new SqlCommand(query, conn);
                cmd.Parameters.AddWithValue("@FirstName", user.FirstName ?? "");
                cmd.Parameters.AddWithValue("@LastName", user.LastName ?? "");
                cmd.Parameters.AddWithValue("@Username", user.Username);
                cmd.Parameters.AddWithValue("@Email", user.Email);
                cmd.Parameters.AddWithValue("@Role", user.Role ?? "Student");

                conn.Open();
                cmd.ExecuteNonQuery();
            }
        }
    }
}