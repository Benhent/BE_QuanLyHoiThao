using Microsoft.EntityFrameworkCore;
using BE_QuanLyHoiThao.Models;

namespace BE_QuanLyHoiThao.Data
{
    public class AppDBContext : DbContext
    {
        public AppDBContext(DbContextOptions<AppDBContext> options) : base(options) { }

        public DbSet<User> Users { get; set; }
        // Add other DbSets as needed
    }
}