const express = require('express');
const mongoose = require('mongoose');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');
const bcrypt = require('bcrypt');
const flash = require('connect-flash');
const path = require('path');
const multer = require('multer'); // Include multer for file uploads

const app = express();

// Set EJS as the view engine
app.set('view engine', 'ejs');

// Specify the "views" directory
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(
  session({
    secret: 'your_secret_key', // Change this to a strong secret
    resave: true,
    saveUninitialized: true,
  })
);
app.use(passport.initialize());
app.use(passport.session());
app.use(flash()); // Enable flash messages

// MongoDB Connection
mongoose
  .connect('mongodb://localhost:27017/userauthdb', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log('Connected to MongoDB');
  })
  .catch((error) => {
    console.error('Error connecting to MongoDB:', error);
  });

// User Schema
const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  profilePicture: String, // Add a field for storing profile picture filename
});

const User = mongoose.model('User', userSchema);

// Passport Configuration
passport.use(
  new LocalStrategy({ usernameField: 'email' }, (email, password, done) => {
    User.findOne({ email: email })
      .then((user) => {
        if (!user) {
          return done(null, false, { message: 'Incorrect email.' });
        }
        bcrypt.compare(password, user.password)
          .then((res) => {
            if (res) {
              return done(null, user);
            } else {
              return done(null, false, { message: 'Incorrect password.' });
            }
          })
          .catch((err) => done(err));
      })
      .catch((err) => done(err));
  })
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  User.findById(id)
    .then((user) => {
      done(null, user);
    })
    .catch((err) => {
      done(err, null);
    });
});

// Configure multer to specify where and how to store uploaded files
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'public/profile-pics'); // Set the destination folder
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname)); // Rename the file with a unique name
  },
});

const upload = multer({ storage });

// Define the landing page route
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

// Define the login route
app.get('/login', (req, res) => {
  res.sendFile(__dirname + '/public/login.html');
});

// Registration form submission
app.post('/register', upload.single('profilePicture'), (req, res) => {
  const { name, email, password } = req.body;
  const profilePicture = req.file ? req.file.filename : ''; // Store the filename in the database

  bcrypt.hash(password, 10, (err, hash) => {
    if (err) {
      console.error('Error hashing password:', err);
      req.flash('error', 'An error occurred during registration.');
      res.redirect('/');
    } else {
      const user = new User({
        name,
        email,
        password: hash,
        profilePicture, // Save the profile picture filename
      });

      user
        .save()
        .then(() => {
          req.flash('success', 'Registration successful! You can now log in.');
          res.redirect('/login');
        })
        .catch((error) => {
          console.error('Error saving data:', error);
          req.flash('error', 'An error occurred during registration.');
          res.redirect('/');
        });
    }
  });
});

// Login form submission
app.post(
  '/login',
  passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login',
    failureFlash: true,
  })
);

// Dashboard route (protected)
app.get('/dashboard', (req, res) => {
  if (req.isAuthenticated()) {
    res.render('dashboard', { user: req.user, errorMessage: req.flash('error'), profilePicture: req.user.profilePicture });
  } else {
    req.flash('error', 'Please log in to access the dashboard.');
    res.redirect('/login');
  }
});

// Logout route
app.get('/logout', (req, res) => {
  req.logout();
  req.flash('success', 'You have been logged out.');
  res.redirect('/login');
});

// Serve static files from the 'public' directory
app.use(express.static('public'));

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});
