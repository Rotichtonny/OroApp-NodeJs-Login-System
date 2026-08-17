var express = require('express');
var path = require('path');
var session = require('express-session');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var flash = require('connect-flash');
var routes = require('./routes/index');
var users = require('./routes/users');

var app = express();

//View Engine
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

//Static folder
app.use(express.static(path.join(__dirname, 'public')));
app.use('/css', express.static(__dirname + '/node_modules/bootstrap/dist/css'));

//BodyParser - using built-in Express parsers (body-parser 1.20.3+ secure, but Express built-ins are preferred)
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

//Express Session Middleware
app.use(session({
    secret: 'secret',
    saveUninitialized: true,
    resave: true
}));

//Passport Middleware
app.use(passport.initialize());
app.use(passport.session());

//Connect-Flash Middleware
app.use(flash());
app.use(function (req, res, next) {
    res.locals.messages = require('express-messages')(req, res);
    next();
});

app.get('*', function (req, res, next) {
    res.locals.user = req.user || null;
    next();
});

//Define Routes
app.use('/', routes);
app.use('/users', users);

app.listen(3000);
console.log('Server started on port 3000');