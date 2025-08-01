const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const MongoStore = require('connect-mongo');

const app = express();
const dotenv = require('dotenv');

dotenv.config({
  path: path.join(__dirname, '../.env')
});

// MongoDB connection
let db;
async function connectToMongo() {
  if (!db) {
    db = await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    console.log('Connected to MongoDB');
  }
  return db;
}

// Models
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const feedbackSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  username: { type: String, required: true },
  rating: { type: Number, required: true, min: 1, max: 5 },
  comment: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

let User, Feedback;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '../public')));

// Session middleware with Mongo store
app.use(
  session({
    secret: 'feedback-website-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 },
    store: MongoStore.create({ mongoUrl: process.env.MONGO_URI })
  })
);

const requireAuth = (req, res, next) => {
  if (req.session.userId) {
    next();
  } else {
    res.redirect('/login.html');
  }
};

app.get('/', (req, res) => {
  if (req.session.userId) {
    res.redirect('/dashboard.html');
  } else {
    res.sendFile(path.join(__dirname, '../public', 'index.html'));
  }
});

app.post('/api/signup', async (req, res) => {
  try {
    await connectToMongo();
    User = mongoose.models.User || mongoose.model('User', userSchema);

    const { username, email, password } = req.body;

    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({ username, email, password: hashedPassword });
    await user.save();

    req.session.userId = user._id;
    req.session.username = user.username;

    res.json({ success: true, message: 'User created successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    await connectToMongo();
    User = mongoose.models.User || mongoose.model('User', userSchema);

    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    req.session.userId = user._id;
    req.session.username = user.username;

    res.json({ success: true, message: 'Login successful' });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.post('/api/feedback', requireAuth, async (req, res) => {
  try {
    await connectToMongo();
    Feedback = mongoose.models.Feedback || mongoose.model('Feedback', feedbackSchema);

    const { rating, comment } = req.body;

    const feedback = new Feedback({
      userId: req.session.userId,
      username: req.session.username,
      rating,
      comment
    });

    await feedback.save();
    res.json({ success: true, message: 'Feedback submitted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/feedbacks', async (req, res) => {
  try {
    await connectToMongo();
    Feedback = mongoose.models.Feedback || mongoose.model('Feedback', feedbackSchema);

    const feedbacks = await Feedback.find().sort({ createdAt: -1 });
    res.json(feedbacks);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/auth/status', (req, res) => {
  res.json({
    authenticated: !!req.session.userId,
    username: req.session.username
  });
});

module.exports = app;
