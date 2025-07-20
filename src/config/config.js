// src/config/config.js
require('dotenv').config();

module.exports = {
  MONGO_URI: process.env.MONGO_URI,
  PORT: process.env.PORT || 5000,
  JWT_SECRET: process.env.JWT_SECRET || 'your_jwt_secret',
  JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN
};
