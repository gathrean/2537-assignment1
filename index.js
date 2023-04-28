require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 8080;

const app = express();
const path = require('path');


const Joi = require("joi");

const expireTime = 8 * 60 * 60 * 1000; // expires after 8 hours (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

const { database } = require('./databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));


app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore, // default is memory store
    saveUninitialized: false,
    resave: true,
  })
);

// Render the home page with options to sign up or sign in if not logged in
app.get('/', (req, res) => {
  if (req.session.authenticated) {
    res.render('home-loggedin', { username: req.session.username });
  } else {
    res.render('home', {});
  }
});



// Render the sign-up page
app.get('/signup', (req, res) => {
  res.render('signup', { error: null });
});

// Process sign-up form submission
app.post('/signup', async (req, res) => {
  const name = req.body.name;
  const email = req.body.email;
  const password = req.body.password;

  // Validate user input
  const schema = Joi.object({
    name: Joi.string().max(20).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ name, email, password });

  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.render('signup', { error: validationResult.error.details[0].message });
    return;
  }

  // Hash the password and save the new user to the database
  const hashedPassword = await bcrypt.hash(password, saltRounds);

  await userCollection.insertOne({ name, email, password: hashedPassword });

  // Create a session and redirect the user to the /members page
  req.session.authenticated = true;
  req.session.username = name;
  req.session.cookie.maxAge = expireTime;
  res.redirect('/members');
});


// Render the log in page
app.get('/login', (req, res) => {
  res.render('signin', { error: null });
});

// Process log in form submission
app.post('/login', async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  // Validate user input
  const schema = Joi.object({
      email: Joi.string().email().required(),
      password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ email, password });

  if (validationResult.error != null) {
      console.log(validationResult.error);
      res.render('signin', { error: 'Invalid email or password' });
      return;
  }

  // Find the user in the database
  const user = await userCollection.findOne({ email });

  if (!user || !(await bcrypt.compare(password, user.password))) {
      res.render('signin', { error: 'Invalid email or password' });
      return;
  }

  // Set session variables and redirect to the members area
  req.session.authenticated = true;
  req.session.username = user.name;
  req.session.cookie.maxAge = expireTime;
  res.redirect('/members');
});

// Log out the user
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});
  
  // Render the members area with a random image
  app.get('/members', isAuthenticated, (req, res) => {
    const images = ['image1.jpeg', 'image2.jpeg', 'image3.jpeg']; // Replace these names with your actual image file names
    const randomImage = images[Math.floor(Math.random() * images.length)];
    res.render('members', {
      username: req.session.username,
      imageUrl: '/images/' + randomImage,
    });
});



  
  
  // Middleware to check if the user is authenticated
  function isAuthenticated(req, res, next) {
    if (req.session.authenticated) {
      return next();
    }
    res.redirect('/signin');
  }
  
  // Add your existing routes here...
  
  app.use(express.static(__dirname + '/public'));

  
  app.get('*', (req, res) => {
    res.status(404);
    res.send('Page not found - 404');
  });
  
  app.listen(port, () => {
    console.log('Node application listening on port ' + port);
  });
  
