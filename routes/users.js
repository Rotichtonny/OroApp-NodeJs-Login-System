var express = require('express');
var router = express.Router();
var mongojs = require('mongojs');
var db = mongojs('oroapp', ['users']);
var bycript = require('bcryptjs');
var passport = require('passport');
var localStrategy = require('passport-local').Strategy;
var { check, validationResult } = require('express-validator');

// Login Page - GET
router.get('/login', function (req, res) {
    res.render('login');
});

// Register Page - get
router.get('/register', function (req, res) {
    res.render('register');
});

// Register Page - POST
router.post('/register', [
    check('fullname', 'Full Names is required').notEmpty(),
    check('email', 'Email field is required').notEmpty(),
    check('email', 'Please use a valid email address').isEmail(),
    check('username', 'Username is required').notEmpty(),
    check('password', 'Password is required').notEmpty(),
    check('password2', 'Password do not match').custom(function(value, { req }) {
        if (value !== req.body.password) {
            throw new Error('Password do not match');
        }
        return true;
    })
], function (req, res) {
    //Get Form Values
    var fullname = req.body.fullname;
    var email = req.body.email;
    var username = req.body.username;
    var password = req.body.password;
    var password2 = req.body.password2;

    //Check for errors - using express-validator 6.x API (compatible with both old and new)
    var error = validationResult(req).array();
    // Fallback for old API if needed (if req.validationErrors exists)
    if (!error.length && typeof req.validationErrors === 'function') {
        var legacy = req.validationErrors();
        if (legacy) error = legacy;
    }
    // Normalize to null if no errors (original code expects truthy check)
    if (error.length === 0) error = null;

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

passport.serializeUser(function (user, done) {
    done(null, user._id);
});

passport.deserializeUser(function (id, done) {
    db.users.findOne({ _id: mongojs.ObjectId(id) }, function (err, user) {
        done(err, user);
    });
});

passport.use(new localStrategy(function (username, password, done) {
    db.users.findOne({ username: username }, function (err, user) {
        if (err) {
            return done(err);
        }
        if (!user) {
            return done(null, false, { message: 'Incorrect Username' });
        }
        bycript.compare(password, user.password, function (err, isMatch) {
            if (err) {
                return done(err);
            }
            if (isMatch) {
                return done(null, user);
            } else {
                return done(null, false, { message: 'Incorrect password' });
            }
        });
    });
}));

//Login -POST
router.post('/login',
    passport.authenticate('local', {
        successRedirect: '/',
        failureRedirect: '/users/login',
        failureFlash: 'Invalid Username Or Password'
    }), function (req, res) {
        console.log('Auth Successfull');
        res.redirect('/');
    }
);

router.get('/logout', function (req, res, next) {
    req.logout(function(err) {
        if (err) { return next(err); }
        req.flash('success', 'You have logged out')
        res.redirect('/users/login');
    });
})

module.exports = router;