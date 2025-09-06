// models/Product.js
const { sequelize, DataTypes } = require('../db');
const User = require('./User');
const Category = require('./Category');

const Product = sequelize.define('Product', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  title: { type: DataTypes.STRING, allowNull: false },
  description: { type: DataTypes.TEXT, allowNull: true },
  price: { type: DataTypes.FLOAT, allowNull: false, defaultValue: 0 },
  image: { type: DataTypes.STRING, allowNull: true }, // path to uploaded image
});

// Associations
User.hasMany(Product, { foreignKey: 'userId' });
Product.belongsTo(User, { foreignKey: 'userId' });

Category.hasMany(Product, { foreignKey: 'categoryId' });
Product.belongsTo(Category, { foreignKey: 'categoryId' });

module.exports = Product;
