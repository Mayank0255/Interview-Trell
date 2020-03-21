var express = require("express"),
    app = express(),
    session = require('express-session'),
    bodyParser = require("body-parser"),
    methodOverride = require("method-override"),
    request = require("request"),
    bcrypt = require('bcrypt-nodejs'),
    passport = require("passport"),
    LocalStrategy = require('passport-local'),
    mysql = require("mysql");

app.use(
    bodyParser.urlencoded({
        extended: true
    })
);
app.use(express.static(__dirname + "/public"));
app.set("view engine", "ejs");
app.use(methodOverride("_method"));

var connection = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "Mayank15$",
    database: "quiz",
    multipleStatements: true
});


app.use(session({
    secret: "System Breached",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

app.use(function(req, res, next) {
    res.locals.currentUser = req.user;
    next();
});

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(function(id, done) {
    connection.query("SELECT * FROM users WHERE id = ? ", [id],
        function(err, rows) {
            done(err, rows[0]);
        });
});

passport.use(
    'local-signup',
    new LocalStrategy({
            usernameField: 'username',
            passwordField: 'password',
            passReqToCallback: true
        },
        function(req, username, password, done) {
            connection.query("SELECT * FROM users WHERE username = ? ", [username], function(err, rows) {
                if (err)
                    return done(err);
                if (rows.length) {
                    return done(null, false, req.flash('signupMessage', 'That is already taken'));
                } else {
                    var newUserMysql = {
                        username: username,
                        password: bcrypt.hashSync(password, null, null)
                    };

                    var insertQuery = "INSERT INTO users (username, password) values (?, ?)";

                    connection.query(insertQuery, [newUserMysql.username, newUserMysql.password],
                        function(err, rows) {
                            newUserMysql.id = rows.insertId;

                            return done(null, newUserMysql);
                        });
                }
            });
        })
);

passport.use(
    'local-login',
    new LocalStrategy({
            usernameField: 'username',
            passwordField: 'password',
            passReqToCallback: true
        },
        function(req, username, password, done) {
            connection.query("SELECT * FROM users WHERE username = ? ", [username],
                function(err, rows) {
                    if (err)
                        return done(err);
                    if (!rows.length) {
                        return done(null, false, req.flash('loginMessage', 'No User Found'));
                    }
                    if (!bcrypt.compareSync(password, rows[0].password))
                        return done(null, false, req.flash('loginMessage', 'Wrong Password'));

                    return done(null, rows[0]);
                });
        })
);

connection.query('USE quiz;');

app.get("/",function(req,res){
    res.render("login");
});

app.post("/login", function(req, res, next) {
    passport.authenticate("local-login", {
        successRedirect: "/index",
        failureRedirect: "/"
    })(req, res);
});

app.get("/register",function(req,res){
    res.render("register");
});

app.post("/register", function(req, res, next) {
    passport.authenticate("local-signup", {
        successRedirect: "/index",
        failureRedirect: "/register"
    })(req, res);
});

app.get("/logout",function(req,res){
    req.logout();
    res.redirect("/");
});

app.get("/index",isLoggedIn, function(req, res) {
    request(
        "https://opentdb.com/api.php?amount=5&category=14&difficulty=medium&type=multiple",
        function(error, response, body) {
            if (!error && response.statusCode == 200) {
                var data = JSON.parse(body);
                // console.log(data.results);
                var score;
                res.render("index", { data: data.results, score: score });
            }
        }
    );
});

app.post("/score",isLoggedIn, function(req, res) {
    console.log(req.body.score);  
    connection.query("INSERT INTO quizscore(score,user_id) VALUES(?,?)",[req.body.score,req.user.id],function(error,results,fields){
        if(error) throw error;
        res.redirect("/history");
    });
});

app.get("/history",isLoggedIn,function(req,res){
    connection.query("SELECT user_id,username,created_at,score FROM users JOIN quizscore ON users.id = quizscore.user_id;",function(error,results,fields){
        if(error) throw error;
        // console.log(results[0]);
        
        res.render("history",{results:results});
    });
});

function isLoggedIn(req,res,next){
    if(req.isAuthenticated()){
        return next();
    }
    res.redirect("/");
};

app.listen(3000, function() {
    console.log("SERVER STARTED AT 3000");
});