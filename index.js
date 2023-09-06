const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const cors = require('cors');
const mysql = require('mysql');
const jwt = require('jsonwebtoken');

const bcrypt = require('bcrypt');
const saltRounds = 10;
const secretKey = 'your-secret-key';

app.use(express.json());
app.use(bodyParser.urlencoded({extended: true}));
app.use(cors());

const db = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: 'root',
    database: 'xtrainer',
});


// Middleware to verify JWT token
function verifyToken(req, res, next) {
    const token = req.headers['authorization'];
  
    if (!token) {
      return res.status(403).json({ message: 'Token missing' });
    }
  
    jwt.verify(token, secretKey, (err, decoded) => {
      if (err) {
        console.log(err);
        return res.status(401).json({ message: 'Token invalid' });
      }
      req.userId = decoded.id;
      next();
    });
  }


app.post('/api/register', (req, res) => {

    const username = req.body.username; 
    const password = req.body.password;

    bcrypt.hash(password, saltRounds, (err, hash) => {
        db.query("INSERT INTO users (username, password) VALUES (?, ?);", [username, hash], (err, result) => {
            console.log(result);
            if(result){
                res.send({ message: "User registered!", status: "true" });
            } else{
                res.send({ message: "Username already taken", status: "false" });
            }
        });
    });
});

app.post('/api/pupil/register', (req, res) => {

    const username = req.body.username; 
    const password = req.body.password;
    const isPupil = true;
    const trainer = req.body.trainer;

    bcrypt.hash(password, saltRounds, (err, hash) => {
        db.query("INSERT INTO users (username, password, isPupil, trainer) VALUES (?, ?, ?, ?);", [username, hash, isPupil, trainer], (err, result) => {
            console.log(result);
            if(result){
                res.send({ message: "Pupil registered!", status: "true" });
            } else{
                res.send({ message: "Username already taken", status: "false" });
            }
        });
    });
});

app.post('/api/login', (req, res) => {

    const username = req.body.username; 
    const password = req.body.password;

    db.query("SELECT * FROM xtrainer.users WHERE username = ?;", [username], (err, result) => {
        if (err){
            console.log(err);
        } 
            if(result.length > 0){
                if(result[0].isPupil == null) {
                    bcrypt.compare(password, result[0].password, (error, response) => {
                        if(response) {
                            const id = result[0].id;
                            const token = jwt.sign({id}, secretKey, {
                                expiresIn: 300,
                            });

                            res.send({auth: true, token: token, result: result})

                        } else{
                            res.send({message: "Wrong password combination"});
                        }
                    });
                } 
                else{
                    res.send({code: 'NAT', message: "User is not a trainer!"});
                }
            } else{
                res.send({code: 'NE', message: "User doesn't exist"});
            }
        
       

    });
});

// Protected route
app.get('/api/users', verifyToken, (req, res) => {

    db.query("SELECT * FROM xtrainer.users WHERE id = ?;", [req.userId], (err, result) => {
        if (err || result.length === 0) {
            return res.status(404);
          } else{
            const username = result[0].username;
            db.query("SELECT * FROM xtrainer.users WHERE trainer = ?;",[username], (error, results) => {
                res.send({result: results});
            });
          }
    });
});






const port = process.env.PORT || 3001;
app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});