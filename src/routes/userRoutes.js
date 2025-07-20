const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const authMiddleware = require('../middleware/authMiddleware'); // Optional: if using authentication

// Register a new user
router.post('/register', userController.registerUser);

// Login an existing user
router.post('/login', userController.loginUser);

// Update user profile (protected route)
router.put('/:id', authMiddleware, userController.updateUserProfile);

// Optional: Add more routes for getting user profile, deleting user, etc.
// router.get('/:id', authMiddleware, userController.getUserProfile);
// router.delete('/:id', authMiddleware, userController.deleteUser);

module.exports = router;