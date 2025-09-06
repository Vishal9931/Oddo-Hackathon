// db.js
const { Sequelize, DataTypes, Op } = require('sequelize');

// Use a local sqlite file called database.sqlite in the project root
const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: './database.sqlite',
  logging: false, // set true if you want SQL logs
});

module.exports = { sequelize, DataTypes, Op };
