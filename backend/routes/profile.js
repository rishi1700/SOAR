const express = require('express');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const auth = require('../middleware/auth');

const router = express.Router();

// Fetch user profile
router.get('/', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    res.json(user);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

// Update user profile
router.put('/', auth, async (req, res) => {
  const { username, email, currentPassword, newPassword } = req.body;

  try {
    let user = await User.findById(req.user.id);

    // Check if current password matches
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ errors: [{ msg: 'Current password is incorrect' }] });
    }

    // Update user details
    if (username) user.username = username;
    if (email) user.email = email;
    if (newPassword) {
      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(newPassword, salt);
    }

    await user.save();
    res.json(user);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

module.exports = router;
