

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

const expireTime = 1 * 60 * 60 * 1000; //expires after 1 hr  (hours * minutes * seconds * millis)

const { ObjectId } = require('mongodb');

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = require('./databaseConnection'); 

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
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));

function sessionValidation(req,res,next) {
	if (req.session.authenticated) {
		return next();
	} else {
		return res.render('index', { title: "Please Sign Up or Log In" });
	}
}

function adminAuthorization(req,res,next) {
    if (req.session.user_type !== 'admin') {
        res.status(403);
        return res.render("error", { title: "No Admin Privileges", errorMsg: "Status Code: 403. Not Authorized.", redirect: "/" });
    }
    else {
		next();
    }
}

app.get('/', sessionValidation, (req,res) => {
    res.redirect('/members');
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

	//If we didn't use Joi to validate and check for a valid URL parameter below
	// we could run our userCollection.find and it would be possible to attack.
	// A URL parameter of user[$ne]=name would get executed as a MongoDB command
	// and may result in revealing information about all users or a successful
	// login without knowing the correct password.
	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/signup', (req,res) => {    
    res.render("signup", { title: "Sign Up" });
});

app.get('/login', (req,res) => {
    res.render("login", { title: "Log In"});
});

app.post('/signupSubmit', async (req,res) => {
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;

	const schema = Joi.object(
		{
            name: Joi.string().max(20).required(),
            email: Joi.string().email().required(),
			password: Joi.string().max(20).required()
		});
	
    const validationResult = schema.validate({name, email, password}, {abortEarly: false});
    
    if (validationResult.error) {
        const missingFields = Array.from(
            new Set(validationResult.error.details.map(e => e.context.key))
        );

        const message = `${missingFields.join(', ')} required.`;
        const formatMessage = message[0].toUpperCase() + message.slice(1);

        return res.render("error", { title: "Sign Up Failed", errorMsg: formatMessage, redirect: "/signup" });
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);
	
    await userCollection.insertOne({ name: name, email: email, password: hashedPassword, user_type: 'user' });
	console.log("Inserted user");
    req.session.authenticated = true; 
    req.session.name = name; 
    req.session.email = email; 
	req.session.cookie.maxAge = expireTime;
	req.session.user_type = 'user';

    res.redirect('/');
});

app.post('/loginSubmit', async (req,res) => {
    var email = req.body.email;
    var password = req.body.password;

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(email);
	if (validationResult.error != null) {
        console.log(validationResult.error);
        return res.render("error", { title: "Login Failed", errorMsg: "Invalid email format.", redirect: "/login" });
	}

    const result = await userCollection.find({email: email}).project({ email: 1, password: 1, _id: 1, name: 1, user_type: 1 }).toArray();

	// console.log(result);
	if (result.length != 1) {
		console.log("user not found");
		return res.render("error", { title: "Login Failed", errorMsg: "Email not registered.", redirect: "/login" });	
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
        req.session.name = result[0].name;
		req.session.email = email;
		req.session.cookie.maxAge = expireTime;
		req.session.user_type = result[0].user_type;

        return res.redirect('/');
		
	}
	else {
		console.log("incorrect password");
			return res.render("error", { title: "Login Failed", errorMsg: "Invalid email/password combination.", redirect: "/login" });	}
});

app.get('/members', sessionValidation, async (req,res) => {
    res.render("members", { title: "Members", name: req.session.name });
});

app.get('/logout', (req,res) => {
	req.session.destroy();
    res.redirect('/');
});

app.get('/admin', sessionValidation, adminAuthorization, async (req,res) => {
	const result = await userCollection.find().project({ name: 1, _id: 1, user_type: 1 }).toArray();
	res.render("admin", { title: "Users", users: result });
});

app.post('/admin/update/:id/', sessionValidation, adminAuthorization, async(req,res) => {
	const userId = req.params.id;
	const role = req.body.role;

	if(role !== 'admin' && role !== 'user') {
		res.status(400);
		return res.render("error", { title: "Update User Type Failed", errorMsg: "Status Code: 400. Invalid user type.", redirect: "/admin" });
	}

	await userCollection.updateOne({_id: new ObjectId(userId)}, {$set: {user_type: role}});
	console.log("succesfully updated role");
	res.redirect('/admin');
});


/* 
app.get('/img/:id', (req,res) => {

    var imageId = req.params.id;

    if (imageId == 1) {
        res.send("<img src='/aussie.jpg' style='width:250px;'>");
    }
    else if (imageId == 2) {
        res.send("<img src='/daschund.jpg' style='width:250px;'>");
    }
    else if (imageId == 3) {
        res.send("<img src='/husky.jpg' style='width:250px;'>");
    }
    else {
        res.send("Invalid img id: " + imageId);
    }
});
*/


app.use(express.static(__dirname + "/public"));

app.get(/.*/, (req,res) => {    
	res.status(404);
	res.render("404");
})

app.listen(port, () => {
	console.log("Node application listening on port " + port);
}); 