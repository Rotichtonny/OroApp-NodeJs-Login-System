var express = require('express');
var router = express.Router();
var mongojs = require('mongojs');
var db = mongojs('oroapp', ['users']);
var bycript = require('bcryptjs');
var passport = require('passport');
var localStrategy = require('passport-local').Strategy;

// Login Page - GET
router.get('/login', function (req, res) {
    res.render('login');
});

// Register Page - get
router.get('/register', function (req, res) {
    res.render('register');
});

// Register Page - POST
router.post('/register', function (req, res) {
    //Get Form Values
    var fullname = req.body.fullname;
    var email = req.body.email;
    var username = req.body.username;
    var password = req.body.password;
    var password2 = req.body.password2;

    //Validation
    req.checkBody('fullname', 'Full Names is required').notEmpty();
    req.checkBody('email', 'Email field is required').notEmpty();
    req.checkBody('email', 'Please use a valid email address').isEmail();
    req.checkBody('username', 'Username is required').notEmpty();
    req.checkBody('password', 'Password is required').notEmpty();
    req.checkBody('password2', 'Password do not match').equals(req.body.password);

    //Check for errors
    var error = req.validationErrors();

    if (error) {
        console.log('Form has errors...');
        res.render('register', {
            error: error,
            fullname: fullname,
            email: email,
            username: username,
            password: password,
            password2: password2
        });
    } else {
        var newUser = {
            fullname: fullname,
            email: email,
            username: username,
            password: password
        }

        bycript.genSalt(10, function (err, salt) {
            bycript.hash(newUser.password, salt, function (err, hash) {
                newUser.password = hash;

                db.users.insert(newUser, function (err, doc) {
                    if (err) {
                        res.send(err);
                    } else {
                        console.log('User Added...');

                        //Success Message
                        req.flash('success', 'You are registered and can now log in');

                        //Redirect after register
                        res.location('/');
                        res.redirect('/');
                    }
                });
            });
        });


    }
});

module.exports = router;