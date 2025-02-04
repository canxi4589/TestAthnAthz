using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace TestIdentityReal.Entity
{
    public class AppUser : IdentityUser
    {
        [MaxLength(100)]
        public string FullName { set; get; } = string.Empty;

        [DataType(DataType.Date)]
        public DateTime? Birthday { set; get; }

        [DataType(DataType.Text)]
        public string Avatar { get; set; } = "https://villagesonmacarthur.com/wp-content/uploads/2020/12/Blank-Avatar.png";
       
        [DataType(DataType.Text)]
        public string? PDF {  get; set; }
        public decimal BalanceWallet { get; set; } = 0;

    }
}
