const express = require('express');
const app = express();
const db = require('./models');
const pbkdf2 = require('pbkdf2');
const crypto = require('crypto');
const session = require('express-session');
const portNumber = process.env.PORT || 3000;

app.use(session({
  secret: 'tacocat',
  resave: true,
  saveUninitialized: true,
  cookie: { maxAge: 60 * 60 * 1000 } 
}))

app.use(express.json());

function encryptPassword(password, pass_salt) {
  var salt = pass_salt ? pass_salt : crypto.randomBytes(20).toString('hex');
  var key = pbkdf2.pbkdf2Sync(
    password, salt, 36000, 256, 'sha256'
  );

  var hash = key.toString('hex');

  return `$${salt}$${hash}`;
}

app.get('/current_user', (req, res) => {
  res.send(req.session.user);
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.send('successfult logout');
})

app.post('/login', (req, res) => {
  if(req.body.username && req.body.password) {
    db.user.findOne(
      { 
        where: 
        { 
          username: req.body.username
        } 
      }).then((user) => {
        if(user) {
          var pass_parts = user.password.split('$');

          // encrypt req.body.password using pass_parts[1]
          let encryptedPass = encryptPassword(req.body.password, pass_parts[1]);

          // compared hashed password with user password
          if(encryptedPass == user.password) {
            req.session.user = user;
            res.send('welcome user: ' + user.username);
          }else {
            res.send('wrong password')
          }
          
        } else {
          res.send('we could not find any users')
        }
      }).catch(() => {
        res.send('There was an error');
      });
  } else {
    res.send('please send a username and password')
  }
});


app.post('/sign-up', (req, res) => {
  if(req.body.username && req.body.password) {
    db.user.create(
      {
        username: req.body.username, 
        password: encryptPassword(req.body.password)
      }
      ).then((user) => {
      res.send(user)
    })
  } else {
    res.send(' please send username and password.');
  }
})


app.listen(portNumber, () =>{
  console.log(`My API is listening on port ${portNumber}`);
})