
require("./utils.js");
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

const ObjectId = require('mongodb').ObjectId;

const expireTime = 24 * 60 * 60 * 1000; //expires after 1 day  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;


var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.set('view engine', 'ejs');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, 
	saveUninitialized: false, 
	resave: true
}
));

function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

async function promote(name, db) {
    await db.collection("users").updateOne({ name: name }, { $set: { user_type: "admin" } });
}

function sessionValidation(req,res,next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.redirect('/login');
    }
}


function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", {error: "Not Authorized"});
        return;
    }
    else {
        next();
    }
}

app.get('/', (req,res) => {
    res.render("index", {session: req.session});
});

app.get('/nosql-injection', async (req,res) => {
	var username = req.query.user;

	if (!username) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+username);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);

	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/about', (req,res) => {
    var color = req.query.color;

    res.render("about", {color: color});
});

app.get('/contact', (req,res) => {
    var missingEmail = req.query.missing;

    res.render("contact", {missing: missingEmail});
});

app.get('/createUser', (req,res) => {
    res.render("createUSer");
});

app.get('/login', (req,res) => {
	if (!req.session.email) {
		res.render("login", {session: req.session});
	} else {res.redirect('/')}
});

app.get('/members', (req, res) => {
	if (req.session.email) {
    	res.render('husky', {
			session: req.session,
			id: Math.random() * 3 + 1});
	} else {res.redirect('/');}
});

app.post('/submitUser', async (req, res) => {
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;
	var usertype = 'user';

    const schema = Joi.object({
        name: Joi.string().min(1).max(20).required(),
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required(),
    });

    const validationResult = schema.validate({ name, email, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.render('signupError', { errorMessage: validationResult.error.details[0].message });
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({ name: name, email: email, user_type: usertype, password: hashedPassword });
    console.log('Inserted user');

    req.session.authenticated = true;
    req.session.email = email;
    req.session.name = name;
    req.session.password = hashedPassword;
	req.session.user_type = usertype;
    req.session.cookie.maxAge = expireTime;

    res.redirect('/members');
});
app.post('/loggingin', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required(),
    });

    const validationResult = schema.validate({ email, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.render("loginError", {errorMessage: req.query.error});
        return;
    }

    const result = await userCollection.find({ email: email }).project({ email: 1, password: 1, name: 1, user_type: 1, _id: 1 }).toArray();

    if (result.length != 1) {
        res.render("loginError", {errorMessage: req.query.error});
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.email = email;
        req.session.name = result[0].name;
        req.session.user_type = result[0].user_type;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/members');
        return;
    }
    else {
        res.render("login_error", {errorMessage: req.query.error});
        return;
    }
});
app.use('/loggedin', sessionValidation);


app.get('/loggedin', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }
    res.render("loggedin");
});

app.get('/loggedin/info', (req,res) => {
    res.render("loggedin-info");
});

app.get('/signout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.log("Error destroying session:", err);
        } else {
            console.log("Session destroyed successfully");
        }
        res.clearCookie('connect.sid');
        res.redirect('/');
    });
});


// app.get('/cat/:id', (req,res) => {
//     var cat = req.params.id;

//     res.render("cat", {cat: cat});
// });


app.get('/admin', sessionValidation, adminAuthorization, async (req,res) => {
	const result = await userCollection.find().project({name: 1, user_type: 1, _id: 1}).toArray();
 
    res.render("admin", {users: result});
});


app.get('/admin/promote/:id', sessionValidation, adminAuthorization, async (req, res) => {
    const userId = req.params.id;

    try {
        await userCollection.updateOne({ _id: new ObjectId(userId) }, { $set: { user_type: "admin" } });
        res.redirect('/admin');
    } catch (err) {
        console.log(err);
        res.status(500).render("errorMessage", { error: "Error promoting user to admin" });
    }
});

app.get('/admin/demote/:id', sessionValidation, adminAuthorization, async (req, res) => {
    const userId = req.params.id;

    try {
        await userCollection.updateOne({ _id: new ObjectId(userId) }, { $set: { user_type: "user" } });
        res.redirect('/admin');
    } catch (err) {
        console.log(err);
        res.status(500).render("errorMessage", { error: "Error demoting user to user" });
    }
});


app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.render("404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 