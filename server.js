const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const mysql = require('mysql2');
const flash = require('connect-flash');
const dotenv = require('dotenv');

dotenv.config();

const app = express();

app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  cookie: { maxAge: 60000 }, // 60 seconds
  resave: false,
  saveUninitialized: false,
}));

app.use(passport.initialize());
app.use(passport.session());
app.use(express.static('public'));

app.use(flash());

app.set('view-engine', 'ejs');

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

app.use(express.urlencoded({ extended: true }));

passport.serializeUser((user, done) => {
  done(null, user.username);
});

passport.deserializeUser(async (username, done) => {
  try {
    const [rows] = await pool.promise().query('SELECT * FROM login WHERE username = ?', [username]);

    if (rows.length === 0) {
      return done(null, false, { message: 'User not found.' });
    }

    const user = rows[0];
    done(null, user);
  } catch (error) {
    return done(error);
  }
});

const secretKey = process.env.JWT_SECRET || 'your-secret-key';

// Routes
app.get('/', (req, res) => {
  const errorMessages = req.flash('error');
  const successMessages = req.flash('success');
  res.render('index.ejs', { errorMessages, successMessages });
});

app.get('/login', (req, res) => {
  if (req.isAuthenticated()) {
    res.redirect('/dashboard');
  } else {
    const errorMessages = req.flash('error');
    const successMessages = req.flash('success');
    res.render('login.ejs', { errorMessages, successMessages });
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const sql = 'SELECT * FROM login WHERE username = ?';
    const [user] = await pool.promise().query(sql, [username]);

    if (user.length === 0) {
      return res.status(401).send('User not found.');
    }

    const passwordMatch = await bcrypt.compare(password, user[0].password);

    if (!passwordMatch) {
      req.flash('error', 'Invalid password.');
      return res.redirect('/login');
    }

    req.flash('login-success', 'You have successfully logged in.');

    req.login(user[0], (err) => {
      if (err) {
        console.error('Error during login:', err);
        return res.status(500).send('Internal server error.');
      }
      const userType = user[0].userType;

      if (userType === 'tenant') {
        return res.redirect('/dashboard');
      } else if (userType === 'landlord') {
        return res.redirect('/admin');
      } else {
        req.flash('error', 'Invalid user type.');
        return res.redirect('/login');
      }
    });
  } catch (err) {
    console.error('Error while querying the database:', err);
    res.status(500).send('Internal server error.');
  }
});


app.get('/register', (req, res) => {
  res.render('register.ejs');
});

app.post('/register', async (req, res) => {
  const {username, password, userType } = req.body;

  try {
    const existingUser = await pool.promise().query('SELECT * FROM login WHERE username = ?', [username]);
    if (existingUser[0].length > 0) {
      return res.status(409).send('User already registered.');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const insertUser = await pool.promise().query('INSERT INTO login (username, password, userType) VALUES (?, ?, ?)', [username, hashedPassword, userType]);
    
    req.flash('message', 'Saved successfully');
    res.redirect('/login');

  } catch (err) {
    console.error('Error while registering user:', err);
    res.status(500).send('Internal server error.');
  }
});
app.get('/home', (req, res) => {
  res.render('dashboard.ejs');
});

app.get('/dashboard', ensureAuthenticated, (req, res) => {
  res.render('dashboard.ejs');
});
app.get('/admin', ensureAuthenticated, (req, res) => {
  res.render('admin.ejs');
});

app.post('/house', (req, res) => {
  const { totalRooms,price,houseType,restrictions,landlordId} = req.body;

  const user = {
    totalRooms: req.body.totalRooms,
    price: req.body.price,
    houseType: req.body.houseType,
    restrictions: req.body.restrictions,
    landlordId: req.body.landlordId,
  };

  const query = 'INSERT INTO houses (totalRooms,price,houseType,restrictions,landlordId) VALUES (?, ?, ?, ?, ?)';
  pool.query(query, [totalRooms,price,houseType,restrictions,landlordId], (error, results) => {
    if (error) {
      console.error(error);
      return res.status(500).send('Error creating the user profile');
    }
    res.redirect('/admin');
  });
});

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
}

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error(err);
    } else {
      res.redirect('/login'); // Redirect to the login page after logout
    }
  });
});

// app.get('/profile', (req, res) => {
//   res.render('profile.ejs');
// });
// app.get('/profile', (req, res) => {
  // res.render('profile.ejs');
  // res.send(`
  //   <form action="/profile" method="post">
  //     <input type="text" name="username" placeholder="Enter a username">
  //     <button type="submit">Fetch Profile</button>
  //   </form>
  // `);
// });

// app.post('/profile', (req, res) => {
//   const { username } = req.body;
  
//   // Query the database to fetch the user's profile based on the provided username
//   const query = 'SELECT * FROM tenats_table WHERE username = ?';
//   pool.query(query, [username], (error, results) => {
//     if (error) {
//       console.error(error);
//       return res.status(500).send('Error fetching profile data');
//     }

//     if (results.length === 0) {
//       return res.status(404).send('User not found');
//     }

//     const user = results[0];
//     res.send(`User Profile: ${user.username}, Email: ${user.email}`);
//   });
// });

app.get('/profile', (req, res) => {
  res.render('profile.ejs');
});

app.post('/profile', (req, res) => {
  const { tenantId, firstName, lastName, email, phone, move_in_date } = req.body;

  const user = {
    tenantId: req.body.tenantId,
    firstName: req.body.firstName,
    lastName: req.body.lastName,
    email: req.body.email,
    phone: req.body.phone,
    move_in_date: req.body.move_in_date,
  };

  const query = 'INSERT INTO tenats_table (tenantId, firstName, lastName, email, phone, move_in_date) VALUES (?, ?, ?, ?, ?, ?)';
  pool.query(query, [tenantId, firstName, lastName, email, phone, move_in_date], (error, results) => {
    if (error) {
      console.error(error);
      return res.status(500).send('Error creating the user profile');
    }
    res.redirect('/profile');
  });
});

app.get('/main', (req, res) => {
  res.render('main.ejs');
});

app.get('/data', (req, res) => {
  pool.query('SELECT~ * FROM tenats_table', (error, results) => {
    if (error) {
      console.error('Error querying the database:', error);
      res.status(500).json({ error: 'Internal server error'});
    } else {
      res.render('data.ejs', { data: results });
    }
  });
});

// app.get('/edit/:username', (req, res) => {
//   const id = req.params.id;
//   pool.query('SELECT * FROM tenats_table WHERE username = ?', [username], (error, result) => {
//     if (error) {
//       console.error('Error querying the database:', error);
//       res.status(500).send('Internal server error');
//     } else {
//       res.render('edit.ejs', { record: result[0] });
//     }
//   });
// });

// app.get('/delete/:username', (req, res) => {
//   const id = req.params.id;
//   pool.query('DELETE FROM tenats_table WHERE username = ?', [username], (error, result) => {
//     if (error) {
//       console.error('Error deleting the record:', error);
//       res.status(500).send('Internal server error');
//     } else {
//       res.redirect('/data');
//     }
//   });
// });

// app.post('/update/:username', (req, res) => {
//   const username = req.params.username;
//   const { name } = req.body;

//   db.query('UPDATE tenats_table SET name = ? WHERE username = ?', [name, username], (error, result) => {
//     if (error) {
//       console.error('Error updating the record:', error);
//       res.status(500).send('Internal server error');
//     } else {
//       res.redirect('/data');
//     }
//   });
// });

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
