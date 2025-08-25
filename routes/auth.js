// backend/routes/auth.js
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Register
router.post('/register', async (req, res) => {
  try {
    const { firstName, lastName, mobileNumber, email, password } = req.body;
    if (!firstName || !mobileNumber || !email || !password) {
      return res.status(400).json({ message: 'Missing required fields' });
    }

    // existing check
    const existing = await User.findOne({ $or: [{ email }, { mobileNumber }] });
    if (existing) return res.status(400).json({ message: 'User with email or mobile already exists' });

    const salt = await bcrypt.genSalt(10);
    const hashed = await bcrypt.hash(password, salt);

    const user = new User({
      firstName, lastName, mobileNumber, email, password: hashed
    });
    await user.save();

    const token = jwt.sign({ id: user._id, email: user.email, firstName: user.firstName }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.json({
      token,
      user: { id: user._id, firstName: user.firstName, lastName: user.lastName, email: user.email, mobileNumber: user.mobileNumber }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Login (accepts email OR mobile)
router.post('/login', async (req, res) => {
  try {
    const { identifier, password } = req.body; // identifier can be email or mobileNumber
    if (!identifier || !password) return res.status(400).json({ message: 'Missing credentials' });

    const user = await User.findOne({ $or: [{ email: identifier }, { mobileNumber: identifier }] });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ id: user._id, email: user.email, firstName: user.firstName }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.json({
      token,
      user: { id: user._id, firstName: user.firstName, lastName: user.lastName, email: user.email, mobileNumber: user.mobileNumber }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
