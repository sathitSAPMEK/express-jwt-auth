require('dotenv').config();
require('./config/database').connect();

const express = require('express');
const User = require('./model/user');
var jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const auth = require('./middleware/auth');

const app = express();
app.use(express.json());

// Login goes here

// Register
app.post('/register',async (req, res) =>{
    // Our register login goes here
    try {
        // Get User Input
        const { firstName, lastName, email, password } = req.body;
        if(!(firstName && lastName && email && password)){
            res.status(400).send("All input is required");
        }

        // Check if User Already Exist
        // Validate if user exist in our database
        const oldUser = await User.findOne({ email });

        if(oldUser){
            return res.status(409).send("User Already exist, Please login")
        }

        // Encrypt user password
        encryptedPassword = await bcrypt.hash(password, 10);

        // Create user in out database
        const user = await User.create({
            firstName,
            lastName,
            email: email.toLowerCase(),
            password: encryptedPassword
        })

        // Create Token
        const token = jwt.sign(
            { user_id: user._id, email },
            process.env.TOKEN_KEY,
            {
                expiresIn: "2h"
            }
        )

        // Save User Token
        user.token = token;

        // return new use
        res.status(201).json(user);
    } catch (error) {
        console.log(error);
    }
});

// Login
app.post('/login',async (req, res) =>{
    // Our login login goes here
    const { email, password } = req.body;
    if(!(email && password)){
        res.status(400).send('All Input is required');
    }

    // Validate if User Exit in our database
    const user = await User.findOne({ email });

    if(user && (await bcrypt.compare(password, user.password))){
        // Create Token
        const token = jwt.sign(
            { user_id: user._id, email },
            process.env.TOKEN_KEY,
            {
                expiresIn: "2h"
            }            
        )

        // save user Token
        user.token = token;
        res.status(200).json(user);
    }else{
        res.status(400).send("Invalid Credentials");
    }

});

app.post('/welcome', auth, (req, res) =>{
    res.status(200).send("Welcome 🙏");
})

module.exports = app;