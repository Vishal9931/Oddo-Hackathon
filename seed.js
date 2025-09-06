// seed.js
const { sequelize } = require('./db');
const Category = require('./models/Category');

async function seed() {
  await sequelize.sync();
  const cats = ['Clothing', 'Electronics', 'Books', 'Home', 'Toys', 'Furniture', 'Accessories'];
  for (const c of cats) {
    await Category.findOrCreate({ where: { name: c } });
  }
  console.log('Categories seeded');
  process.exit(0);
}
seed();
