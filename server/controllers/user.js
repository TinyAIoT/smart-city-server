import bcrypt from 'bcryptjs';
import User from '../models/User.js';
import jwt from 'jsonwebtoken';
import tryCatch from './utils/tryCatch.js';

export const register = tryCatch(async (req, res) => {
  const { name, email, password } = req.body;
  if (password.length < 6)
    return res.status(400).json({
      success: false,
      message: 'Password must be 6 characters or more',
    });
  const emailLowerCase = email.toLowerCase();
  const existedUser = await User.findOne({ email: emailLowerCase });
  if (existedUser)
    return res
      .status(400)
      .json({ success: false, message: 'User already exists!' });
  const hashedPassword = await bcrypt.hash(password, 12);
  const user = await User.create({
    name,
    email: emailLowerCase,
    password: hashedPassword,
  });
  const { _id: id, grouptag, photoURL, role, active } = user;
  const token = jwt.sign({ id, name, grouptag, photoURL, role }, process.env.JWT_SECRET, {
    expiresIn: '1h',
  });
  res.status(201).json({
    success: true,
    result: { id, name, email: user.email, grouptag, photoURL, token, role, active },
  });
});

export const login = tryCatch(async (req, res) => {
  const { email, password } = req.body;

  const emailLowerCase = email.toLowerCase();
  const existedUser = await User.findOne({ email: emailLowerCase });
  if (!existedUser)
    return res
      .status(404)
      .json({ success: false, message: 'User does not exist!' });
  const correctPassword = await bcrypt.compare(password, existedUser.password);
  if (!correctPassword)
    return res
      .status(400)
      .json({ success: false, message: 'Invalid credentials' });

  const { _id: id, name, grouptag, photoURL, role, active } = existedUser;
  if (!active)
    return res.status(400).json({
      success: false,
      message: 'This account has been suspended! Try to contact the admin',
    });
  const token = jwt.sign({ id, name, grouptag, photoURL, role }, process.env.JWT_SECRET, {
    expiresIn: '1h',
  });
  res.status(200).json({
    success: true,
    result: { id, name, email: emailLowerCase, grouptag, photoURL, token, role, active },
  });
});

export const updateProfile = tryCatch(async (req, res) => {
  const fields = req.body?.photoURL
    ? { name: req.body.name, grouptag: req.body.grouptag, photoURL: req.body.photoURL }
    : { name: req.body.name, grouptag: req.body.grouptag, };
  const updatedUser = await User.findByIdAndUpdate(req.user.id, fields, {
    new: true,
  });
  const { _id: id, name, grouptag, photoURL, role } = updatedUser;

  const token = jwt.sign({ id, name, grouptag, photoURL, role }, process.env.JWT_SECRET, {
    expiresIn: '1h',
  });
  res.status(200).json({ success: true, result: { name, grouptag, photoURL, token } });
});

export const getUsers = tryCatch(async (req, res) => {
  const users = await User.find().sort({ _id: -1 });
  res.status(200).json({ success: true, result: users });
});

export const updateStatus = tryCatch(async (req, res) => {
  const { role, active } = req.body;
  await User.findByIdAndUpdate(req.params.userId, { role, active });
  res.status(200).json({ success: true, result: { _id: req.params.userId } });
});
