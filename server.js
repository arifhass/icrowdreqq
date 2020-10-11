var express = require('express');
var passport = require('passport');
var GoogleStrategy = require("passport-google-oauth20").Strategy;
var app = express();
var crypto = require('crypto');
const flash = require("connect-flash");
app.use(flash());
var nodemailer = require("nodemailer");
var async = require("async");
const jwt = require('jsonwebtoken');
var bodyParser = require("body-parser");
var mongoose = require("mongoose");
var Mailchimp = require('mailchimp-api-v3')
mongoose.Promise = global.Promise;
const keys = require("./config/keys");
const User = require("./models/User");
const cors = require('cors');
require('dotenv').config()
const mailgun = require("mailgun-js")
const DOMAIN = 'sandbox6f45f044637c413e85e890d65d455603.mailgun.org';
// const mg = mailgun({ apiKey: process.env.MAILGUN_APIKEY, domain: DOMAIN });
const session = require('express-session')
app.use(session({
    cookie: { maxAge: 60000 },
    secret: 'woot',
    resave: false,
    saveUninitialized: false
}));

mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useCreateIndex: true
});
// mongoose.connect("mongodb+srv://abaid_267:abaid_267@cluster0.zxvlg.mongodb.net/dataname?retryWrites=true&w=majority", {
//     useNewUrlParser: true,
//     useUnifiedTopology: true,
//     useCreateIndex: true
// });
let user = new User;
// var User = mongoose.model('User', UserSchema);
// var user = new UserModel(req.body)

app.use(express.json());
app.use(cors())

var { body, validationResult } = require('express-validator');
var api = express.Router();
app.use(bodyParser.urlencoded({
    extended: true
}));
const bcrypt = require('bcryptjs');

var db = mongoose.connection;
db.on('error', console.log.bind(console, "connection error"));
db.once('open', function (callback) {
    console.log("connection succeeded");
});

app.use(bodyParser.json());
app.use(express.static('public'));

passport.use(
    new GoogleStrategy({
        clientID: keys.googleClientID,
        clientSecret: keys.googleClientSecret,
        callbackURL: '/auth/google/redirect'
    },
        (accessToken, refreshToken, profile, done) => {
            console.log("access token", accessToken)
            console.log("refresh token", refreshToken)
            console.log("profile", profile)
            console.log("done", done)
        })
)

app.get('/auth/google', passport.authenticate('google',
    {
        scope: ['profile', 'email']
    }
));
// passport.authenticate('google', {failureRedirect: '/login'}
app.get('/auth/google/redirect', (req, res) => {
    res.redirect('/homepage');
});

app.post('/register', [
    body('country', 'Country name is required').notEmpty(),
    body('fname', 'First name is required').notEmpty(),
    body('lname', 'Last name is required').notEmpty(),
    body('email', 'Email is required').notEmpty(),
    body('email', 'Email is invalid').isEmail(),
    body('password', 'Password is required').notEmpty(),
    body('password', 'Password should be 8 or more characters long').isLength({ min: 8 }),
    body('city', 'City is required').notEmpty(),
], (req, res) => {
    addEmailToMailchimp(req.body.email);
    const fname = req.body.fname;
    const lname = req.body.lname;
    const email = req.body.email;
    const password = req.body.password;
    const password2 = req.body.password2;
    const mnum = req.body.mnum;
    const city = req.body.city;
    const region = req.body.region;
    const address = req.body.address;
    const pcode = req.body.pcode;

    if (password !== password2) {
        throw new Error('Password does not match');
    }

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() })
    }

    db.collection('details').findOne({ email }).then(user => {
        if (user) {
            return res.status(400).json({ error: [{ msg: 'Email already exists.' }] })
        }

        var data = {
            "fname": fname,
            "lname": lname,
            "email": email,
            "password": password,
            "mnum": mnum,
            "city": city,
            "region": region,
            "address": address,
            "pcode": pcode
        }

        bcrypt.genSalt(10, function (err, salt) {
            bcrypt.hash(data.password, salt, function (err, hash) {
                if (err) {
                    console.log(err);
                }
                data.password = hash;
                db.collection('details').insertOne(data, function (err, collection) {
                    if (err) throw err;
                    console.log("Record inserted Successfully");
                    return res.redirect('login');
                });
            });

        })
    });


});

app.post('/login',
    body('email', 'Email is required').notEmpty(),
    body('email', 'Email is invalid').isEmail(),
    body('password', 'Password is required').notEmpty(),
    (req, res) => {
        let { email, password } = req.body;
        db.collection('details').findOne({ email }).then(user => {
            if (!user) {
                return res.status(400).json({ error: [{ msg: 'Email not found.' }] })
            }

            bcrypt.compare(password, user.password).then(match => {
                if (!match) {
                    return res.status(400).json({ error: [{ msg: 'Invalid Password' }] })
                }
                return res.redirect('homepage');
            })
        });
    });

// app.post('/reset', 
// // body('email', 'Email is required').notEmpty(),
// (req, res) => {
//     const {email} = req.body;

//     User.findOne({email}), (err, user) => {
//         if(err || !user) {
//             return res.status(400).json({error:"User with this email doesn't exist."});
//         }
//         const token =jwt.sign({email: user.email}, process.env.RESET_KEY, {expiresIn: '20m'});
//         const data = {
//             from: 'noreply@icrowd.com',
//             to: email,
//             subject: 'Forgot password link',
//             html: `
//             <h2> sjklsdnvmsnvs </h2>
//             <p> ${process.env.CLIENT_URL}/reset/${token}</p>
//             `
//         };

//         return user.updateOne({reset: token}, function (err, success){
//             if(err) {
//                 return res.status(400).json({error: "reset password link err"});
//             }
//             else {
//                 mg.messages().send(data, function (error, body) {
//                     if(error){
//                         return res.json({
//                             error: err.message
//                         })
//                     }
//                     return res.redirect('login');
//                     // return res.json({message: 'Email has been sent, kindly reset your password'})
//                     // return res.redirect('login');
//                 });
//             }
//         })
//     }

// })
app.post('/forgot',
    body('email', 'Email is required').notEmpty(),
    body('email', 'Email is invalid').isEmail(),
    function (req, res, next) {
        // let { email} = req.body;    
        async.waterfall([
            function (done) {
                crypto.randomBytes(20, function (err, buf) {
                    var token = buf.toString('hex');
                    done(err, token);
                });
            },
            function (token, done) {

                db.collection('details').findOne({ email: req.body.email }, function (err, user) {
                    if (!user) {
                        req.flash('error', "Account does not exist.");
                        return res.status(400).json({ error: [{ msg: 'Email not found.' }] });
                    }

                    user.resetPasswordToken = token;
                    user.resetPasswordExpires = Date.now() + 3600000;
                    db.collection('details').updateOne({ email: req.body.email },
                        { $set: { resetPasswordToken: token, resetPasswordExpires: Date.now() + 3600000 } },
                        function (err, docs) {
                            if (err) throw err
                            done(err, token, user)
                        });
                    console.log(user)
                });
            },
            function (token, user, done) {
                var smtpTransport = nodemailer.createTransport({
                    service: 'Hotmail',
                    auth: {
                        user: process.env.EMAIL,
                        pass: process.env.GMAILPWD
                    }
                });
                var mailOptions = {
                    to: user.email,
                    from: process.env.EMAIL,
                    subject: 'reset pwd',
                    text: `<a href="http://${req.headers.host}/reset/${token}">click link</a>`,
                    // text: ' djcnskcns,mc click link' +
                    //     'http://' + req.headers.host + '/reset/' + token + '\n\n' + 'vm s,dv smv ,sv s,'
                };
                smtpTransport.sendMail(mailOptions, function (err) {
                    console.log('mail sent')
                    req.flash('sucess', 'ksdbcjks' + user.email + 'cjksnmnsc');
                    done(err, 'done');
                });
            }
        ], function (err) {
            if (err) return next(err);
            res.redirect('/forgot');
        });
    });

app.get('/reset/:token', function (req, res) {

    db.collection('details').findOne({ resetPasswordToken: req.params.token }, function (err, user) {

        if (!user) {
            req.flash('error', 'Password reset token is invalid or has expired.');
            return res.redirect('/forgot');
        }
        res.sendFile('./reset.html', { root: __dirname });
    });
});
// 
app.post('/reset/:token', function (req, res) {
    async.waterfall([
        function (done) {
            db.collection('details').findOne({ resetPasswordToken: req.params.token }, function (err, user) {
                if (!user) {
                    return res.status(400).json({ error: [{ msg: 'link has expired or is invalid' }] });
                }
                console.log(user)
                let { password, password2 } = req.body
                console.log(password, password2)
                if (password === password2) {
                    bcrypt.genSalt(10, function (err, salt) {
                        bcrypt.hash(password, salt, function (err, hash) {
                            if (err) {
                                console.log(err);
                            }
                            password = hash;
                            db.collection('details').updateOne({ resetPasswordToken: user.resetPasswordToken }, { $set: { password: password } }, function (err, collection) {
                                if (err) throw err;
                                done(err, 'user')
                            });
                        });

                    })
                    // user.setPassword(req.body.password, function (err) {
                    //     user.resetPasswordToken = undefined;
                    //     user.resetPasswordExpires = undefined;

                    //     user.save(function (err) {
                    //             done(err, user);
                    //     });
                    // })
                } else {
                    return res.status(400).json({ error: [{ msg: 'Passwords do not match' }] });
                }
            });
        }
        // , function (user, done) {
        //     done(err, 'done')
        //     res.redirect('login')
        // }
    ], function (err) {
        if (err) return next(err);
        res.redirect('/login');
    })
})

app.get('/', function (req, res) {
    res.sendFile('./register.html', { root: __dirname });
})


app.get('/forgot', function (req, res) {
    res.sendFile('./forgot.html', { root: __dirname });
})

// app.get('/reset/:token ', function (req, res) {
//     User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function (err, user) {
//         if (!user) {
//             req.flash('error', 'link has invalid or expired');
//             return res.redirect('/forgot');
//         }
//         res.sendFile('./reset.html', { token: req.params.token });
//     });
// });

app.get('/login', function (req, res) {
    res.sendFile('./login.html', { root: __dirname });
})

app.get('/homepage', function (req, res) {
    res.sendFile('./homepage.html', { root: __dirname });
})
const port = process.env.PORT || 7000;
app.listen(port, () => {
    console.log(`Server working on port: ${port}`);
})

function addEmailToMailchimp(email) {
    var request = require("request");

    var options = {
        method: 'POST',
        url: 'https://us17.api.mailchimp.com/3.0/lists/b9a4bd2222/members',
        headers:
        {
            'postman-token': 'ec3d5ea1-fee8-cabf-5e0d-0085b1af2202',
            'cache-control': 'no-cache',
            'content-type': 'application/json',
            authorization: 'Basic YW55c3RyaW5nOjliOWVhNjBhNDllZGM0Njc1ZGQzMGM4NGYwZGFjZjM5LXVzMTc='
        },
        body:
        {
            email_address: email,
            status: 'subscribed'
        },
        json: true
    };

    request(options, function (error, response, body) {
        if (error) throw new Error(error);

        console.log(body);
    });

}