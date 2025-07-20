// src/app.js
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const userRoutes = require('./routes/userRoutes');
const { errorHandler } = require('./middlewares/errorMiddleware');

const app = express();

// Middleware setup
app.use(helmet()); // Security headers
app.use(cors()); // Enable CORS
app.use(express.json()); // Parse JSON bodies
app.use(morgan('combined')); // HTTP request logging

// Routes
app.use('/api/users', userRoutes);

// Error handling middleware
app.use(errorHandler);

module.exports = app;


// src/server.js
const mongoose = require('mongoose');
const app = require('./app');
const { MONGO_URI, PORT } = require('./config/config');

// Connect to MongoDB
mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('Connected to MongoDB');
  app.listen(PORT, () => {
    console.log(`User service running on port ${PORT}`);
  });
}).catch((error) => {
  console.error('MongoDB connection error:', error);
  process.exit(1);
});


// src/models/User.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true
  },
  roles: {
    type: [String],
    default: ['student']
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (err) {
    next(err);
  }
});

// Method to compare password
userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('User', userSchema);


// src/routes/userRoutes.js
const express = require('express');
const {
  registerUser,
  loginUser,
  getUserProfile
} = require('../controllers/userController');
const { protect } = require('../middlewares/authMiddleware');

const router = express.Router();

// Public routes
router.post('/register', registerUser);
router.post('/login', loginUser);

// Protected route
router.get('/profile', protect, getUserProfile);

module.exports = router;


// src/controllers/userController.js
const User = require('../models/User');
const generateToken = require('../utils/generateToken');

// Register new user
const registerUser = async (req, res, next) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ message: 'Please provide all required fields' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already in use' });
    }

    const user = new User({ username, email, password });
    await user.save();

    res.status(201).json({
      _id: user._id,
      username: user.username,
      email: user.email,
      roles: user.roles,
      token: generateToken(user._id)
    });
  } catch (error) {
    next(error);
  }
};

// Login user
const loginUser = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (user && (await user.comparePassword(password))) {
      res.json({
        _id: user._id,
        username: user.username,
        email: user.email,
        roles: user.roles,
        token: generateToken(user._id)
      });
    } else {
      res.status(401).json({ message: 'Invalid email or password' });
    }
  } catch (error) {
    next(error);
  }
};

// Get user profile
const getUserProfile = async (req, res, next) => {
  try {
    // req.user is set in auth middleware
    const user = await User.findById(req.user.id).select('-password');
    if (user) {
      res.json(user);
    } else {
      res.status(404).json({ message: 'User not found' });
    }
  } catch (error) {
    next(error);
  }
};

module.exports = {
  registerUser,
  loginUser,
  getUserProfile
};


// src/middlewares/authMiddleware.js
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { JWT_SECRET } = require('../config/config');

const protect = async (req, res, next) => {
  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    try {
      token = req.headers.authorization.split(' ')[1];
      const decoded = jwt.verify(token, JWT_SECRET);
      req.user = await User.findById(decoded.id).select('-password');
      if (!req.user) {
        return res.status(401).json({ message: 'User not found' });
      }
      next();
    } catch (error) {
      return res.status(401).json({ message: 'Not authorized, token failed' });
    }
  }

  if (!token) {
    return res.status(401).json({ message: 'Not authorized, no token' });
  }
};

module.exports = { protect };


// src/middlewares/errorMiddleware.js
const errorHandler = (err, req, res, next) => {
  const statusCode = res.statusCode === 200 ? 500 : res.statusCode;
  res.status(statusCode);
  res.json({
    message: err.message,
    stack: process.env.NODE_ENV === 'production' ? null : err.stack
  });
};

module.exports = { errorHandler };


// src/utils/generateToken.js
const jwt = require('jsonwebtoken');
const { JWT_SECRET, JWT_EXPIRES_IN } = require('../config/config');

const generateToken = (id) => {
  return jwt.sign({ id }, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN || '1h'
  });
};

module.exports = generateToken;


// src/config/config.js
require('dotenv').config();

module.exports = {
  MONGO_URI: process.env.MONGO_URI,
  PORT: process.env.PORT || 5000,
  JWT_SECRET: process.env.JWT_SECRET || 'your_jwt_secret',
  JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN
};

