// models/Category.js
const { sequelize, DataTypes } = require('../db');

const Category = sequelize.define('Category', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  name: { type: DataTypes.STRING, unique: true, allowNull: false }
});

module.exports = Category;
