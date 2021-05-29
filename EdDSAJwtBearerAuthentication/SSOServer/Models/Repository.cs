using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SSOServer.Models
{
    public class Repository
    {
        private static List<User> Users = new List<User>
            {
            new User(1, "Maria", "Sanders", "msandesr@northwind.com", "12345",
            new string[]{"Admin" }),
            new User(2, "Pedro", "Flores", "pflores@northwind.com", "12345",
            new string[]{"Accountant" }),
            new User(3, "Estela", "Castillo", "ecastillo@northwind.com", "12345",
            new string[]{"Selller"}),
            new User(4, "Gloria", "Ruiz", "gruiz@northwind.com", "12345",
            new string[]{"Seller", "Accountant"})
            };
     public static User GetUser(string email,string password)
        {
            return Users.FirstOrDefault(u => u.Email == email && u.Password == password);
        }
    }
}
