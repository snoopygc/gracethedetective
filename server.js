const express = require('express');
const session = require('express-session');
const path = require('path');
const fs = require('fs').promises;
const bodyParser = require("body-parser");
const mysql = require('mysql2');
const nodemailer = require('nodemailer');
const smtpTransport = require('nodemailer-smtp-transport');
const bcrypt = require('bcryptjs');
const app = express();
const port = 3500;

app.set("views", path.join(__dirname, "views"));
app.set('view engine', 'ejs');

// MySQL Database configuration
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '', 
    database: 'final' 
});

connection.connect((err) => {
    if (err) {
        console.error('Database connection failed:', err);
        return;
    }
    console.log('Connected to MySQL database.');
});

// File paths
const counterFile = path.join(__dirname, 'counter.txt');
const ipLogFile = path.join(__dirname, 'ip_log.json');

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// Authentication middleware
const isAuthenticated = (req, res, next) => {
    if (req.session.user) {
        next();
    } else {
        res.redirect('/login');
    }
};

// Apply authentication middleware BEFORE static file serving
app.use((req, res, next) => {
    if (req.path !== '/login' &&
        req.path !== '/login.html' &&
        !req.path.match(/\.(css|js|jpg|png|gif|ico)$/)) {
        isAuthenticated(req, res, next);
    } else {
        next();
    }
});

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// Ensure counter and log files exist
async function ensureFilesExist() {
    try {
        await fs.access(counterFile).catch(() => fs.writeFile(counterFile, '0'));
        await fs.access(ipLogFile).catch(() => fs.writeFile(ipLogFile, '{}'));
    } catch (error) {
        console.error('Error ensuring files exist:', error);
        throw error;
    }
}

// Update visit count
async function updateVisitCount(ip) {
    const countData = await fs.readFile(counterFile, 'utf-8');
    let visitCount = parseInt(countData, 10) || 0;

    const ipLogs = JSON.parse(await fs.readFile(ipLogFile, 'utf-8'));
    if (!ipLogs[ip] || Date.now() - ipLogs[ip] >= 24 * 60 * 60 * 1000) { // Once per day
        visitCount++;
        ipLogs[ip] = Date.now();
        await fs.writeFile(counterFile, visitCount.toString());
        await fs.writeFile(ipLogFile, JSON.stringify(ipLogs));
    }
    return visitCount;
}

// Routes

// Login page route
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Login route (updated with password handling)
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const sql = 'SELECT * FROM users WHERE username = ?';
    connection.query(sql, [username], async (err, results) => {
        if (err) {
            console.error('Error querying user:', err);
            return res.status(500).json({ message: 'Database error' });
        }
        if (results.length === 0) {
            console.log('User not found');
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
        try {
            const storedPassword = results[0].password;
            console.log('Stored password:', storedPassword);
            console.log('Provided password:', password);
            
            let isPasswordMatch;
            if (storedPassword.startsWith('$2b$') || storedPassword.startsWith('$2a$')) {
                // The password is hashed
                isPasswordMatch = await bcrypt.compare(password, storedPassword);
            } else {
                // The password is not hashed (legacy case)
                isPasswordMatch = (password === storedPassword);
                
                // If the password matches, update it to a hashed version
                if (isPasswordMatch) {
                    const hashedPassword = await bcrypt.hash(password, 10);
                    const updateSql = 'UPDATE users SET password = ? WHERE username = ?';
                    connection.query(updateSql, [hashedPassword, username], (updateErr) => {
                        if (updateErr) {
                            console.error('Error updating password:', updateErr);
                        } else {
                            console.log('Password updated to hashed version');
                        }
                    });
                }
            }
            
            console.log('Password match result:', isPasswordMatch);
            
            if (!isPasswordMatch) {
                console.log('Password mismatch');
                return res.status(401).json({ success: false, message: 'Invalid credentials' });
            }
            req.session.user = username;
            res.redirect('/');
        } catch (error) {
            console.error('Error comparing password:', error);
            return res.status(500).json({ message: 'Server error' });
        }
    });
});

// Logout route
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

// Registration route (updated with password hashing)
app.post('/register', async (req, res) => {
    const { username, password, email } = req.body;
    try {
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        console.log('Original password:', password);
        console.log('Hashed password:', hashedPassword);
        
        const sql = 'INSERT INTO users (username, password, email) VALUES (?, ?, ?)';
        connection.query(sql, [username, hashedPassword, email], (err) => {
            if (err) {
                console.error('Error inserting user:', err);
                return res.status(500).json({ message: 'Database error' });
            }
            res.status(200).json({ message: 'User registered successfully' });
        });
    } catch (error) {
        console.error('Error hashing password:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Home route with visit counting, requiring authentication
app.get('/', isAuthenticated, async (req, res) => {
    try {
        const visitCount = await updateVisitCount(req.ip);
        let midtermHtml = await fs.readFile(path.join(__dirname, 'public', 'midterm.html'), 'utf8');
        midtermHtml = midtermHtml.replace('{{VISIT_COUNT}}', `${visitCount.toLocaleString()} visits`);
        res.send(midtermHtml);
    } catch (error) {
        console.error('Error handling visit:', error);
        res.status(500).send('An error occurred');
    }
});

// Function to update existing passwords
async function updateExistingPasswords() {
    const sql = 'SELECT id, password FROM users';
    connection.query(sql, async (err, results) => {
        if (err) {
            console.error('Error fetching users:', err);
            return;
        }
        
        for (const user of results) {
            if (!user.password.startsWith('$2b$') && !user.password.startsWith('$2a$')) {
                const hashedPassword = await bcrypt.hash(user.password, 10);
                const updateSql = 'UPDATE users SET password = ? WHERE id = ?';
                connection.query(updateSql, [hashedPassword, user.id], (updateErr) => {
                    if (updateErr) {
                        console.error(`Error updating password for user ${user.id}:`, updateErr);
                    } else {
                        console.log(`Password updated for user ${user.id}`);
                    }
                });
            }
        }
    });
}

function sendmail(toemail, subject, html) {
    const transporter = nodemailer.createTransport({
        host: 'smtp.gmail.com',
        service: 'gmail',
        auth: {
            user: 'ganyaratpz@gmail.com',
            pass: 'vong mhwf tsyo scpi' 
        }
    });

    // send mail with defined transport object
    let mailOptions = {
        from: '"yourGC - Test mail" <snoopygc@gmail.com>',
        to: toemail,    
        subject: subject, 
        html: html
    };

    // send mail with defined transport object
    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log(error);
            res.send('ERROR cannot send email TRY AGAIN later !');
        }
        else {
            // console.log('INFO EMAIL:', info);
            console.log("Send email successfulllllll");
        }
    });
}

app.get("/checkforgot", function(request, response) {
    response.sendFile(path.join(__dirname + "/forgot.html"));
});

app.post("/checkforgot", function(req, res) {
    var useruser = req.body.username;
    console.log(useruser);

    if (useruser) {
        connection.query(
            "SELECT * FROM users WHERE username = ?", useruser, 
            function(errM, rowM) {
                if (errM) {
                    console.error(errM);
                    return res.status(500).send("Database error");
                }

                if (rowM.length > 0) {
                    // Generate a new random password
                    let randomPass = Math.random().toString(36).substring(2, 10);
                    var emails = rowM[0].email;
                    var subject = "Password Changed !";
                    var html = "Hi there " + rowM[0].username + "<br><br>" +
                        "Your Password for GRACE the detective is now changed by your request !<br>" + 
                        "New Password : &nbsp;" + randomPass + "<br>" +
                        "Use this RANDOM password to enter the server and you can change it to yours later" + "<br><br><br>Big Thanks<br>GRACE the Detective";
                    
                    sendmail(emails, subject, html);
                    console.log(emails);

                    // Update Password
                    bcrypt.genSalt(10, function(err, salt) {
                        if (err) {
                            console.error(err);
                            return res.status(500).send("Error generating salt");
                        }

                        bcrypt.hash(randomPass, salt, function(err, hash) {
                            if (err) {
                                console.error(err);
                                return res.status(500).send("Error hashing password");
                            }

                            connection.query(
                                "UPDATE users SET password = ? WHERE username = ?", [hash, useruser],
                                function(err) {
                                    if (err) {
                                        console.error(err);
                                        return res.status(500).send("Error updating password");
                                    }

                                    const textMSG = 'Sending new passsword to your email "' + rowM[0].email + '"<br>Please check your mail inbox';
                                    res.render("index_forgot", {
                                        message: textMSG,
                                        user_name: useruser,
                                        vhf1: 'hidden',
                                        vhf2: 'visible'
                                    });
                                }
                            );
                        });
                    });
                } else {
                    res.render("index_forgot", {
                        message: "Sorryyy Data not found<br> Are you already be our member?",
                        user_name: useruser,
                        vhf1: 'visible',
                        vhf2: 'hidden'
                    });
                }
            }
        );
    } else {
        res.render("index_forgot", {
            message: "Input your data first !!",
            vhf1: 'visible',
            vhf2: 'hidden'
        });
    }
});

app.post('/change_password', isAuthenticated, async (req, res) => {
    const { newPassword } = req.body;

    try {
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

        const sql = 'UPDATE users SET password = ? WHERE username = ?';
        connection.query(sql, [hashedPassword, req.session.user], (err) => {
            if (err) {
                console.error('Error updating password:', err);
                return res.status(500).send('Database error');
            }
            res.redirect('/checkforgot');
        });
    } catch (error) {
        console.error('Error hashing password:', error);
        res.status(500).send('Server error');
    }
});

app.get("/checkLogin", function (req, res) {
    res.sendFile(path.join(__dirname + "/login_auth.html"));
});

    app.post("/checklogin", function (req, res) {
        var useruser = req.body.username;
        var user_password = req.body.password;

        if (useruser && user_password) {
            connection.query(
                "SELECT * FROM users WHERE username = ?", [useruser],
                function (err, results) {
                    if (err) {
                        console.error(err);
                    }

                    if (results.length > 0) {
                        bcrypt.compare(user_password, results[0].password, function (err, resultt) {
                            if (err) {
                                console.error(err);
                            }

                            if (resultt === true) {
                                req.session.loggedin = true;
                                req.session.userID = results[0].username;

                                console.log(user_password, results[0].password);
                                console.log(resultt);
                                res.redirect("/midterm.html");
                            } else {
                                res.render("index_error", {
                                    message: "USER or PASSWORD incorrect ! Register to be our member firsttt",
                                    user_id: useruser
                                });
                            }
                        });
                    } else {
                        res.render("index_error", {
                            message: "USER or PASSWORD incorrect ! Register to be our member firsttt",
                            user_id: useruser
                        });
                    }
                }
            );
        } else {
            res.render("index_error", {
                message: "Enter ALL your information please",
                user_id: useruser
            });
        }
    });
    
// Start server
async function startServer() {
    await ensureFilesExist();
    await updateExistingPasswords();
    app.listen(port, () => {
        console.log(`Server running at http://localhost:${port}`);
    });
}

startServer();