const bcrypt = require('bcryptjs');
const User = require('../models/userModel');
const { validateRegistration } = require('../utils/validate');

const jwt = require('jsonwebtoken');

exports.registerUser = async (req, res) => {
  try {
    // Validate the request body
    const { error } = validateRegistration(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    // Check if the user already exists
    let user = await User.findOne({ email: req.body.email });
    if (user) return res.status(400).send('User already registered.');

    // Hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(req.body.password, salt);

    // Create a new user
    user = new User({
      email: req.body.email,
      password: hashedPassword,
    });

    await user.save();
    res.send('User registered successfully');
  } catch (error) {
    res.status(500).send('Server error');
  }
};


exports.loginUser = async (req, res) => {
  try {
    const { error } = validateRegistration(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    const user = await User.findOne({ email: req.body.email });
    if (!user) return res.status(400).send('Invalid email or password.');

    const validPassword = await bcrypt.compare(req.body.password, user.password);
    if (!validPassword) return res.status(400).send('Invalid email or password.');

    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.header('x-auth-token', token).send(`Login successful use this token ${token}`);
  } catch (error) {
    res.status(500).send('Server error');
  }
};
