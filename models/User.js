// models/User.js
const { sequelize, DataTypes } = require('../db');

const User = sequelize.define('User', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  email: { type: DataTypes.STRING, unique: true, allowNull: false },
  passwordHash: { type: DataTypes.STRING, allowNull: false },
  username: { type: DataTypes.STRING, allowNull: true }
});

module.exports = User;
