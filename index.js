
// require("./utils.js");

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

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

// var {database} = include('databaseConnection');
var {database} = require('./databaseConnection'); 

const userCollection = database.db(mongodb_database).collection('users');

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

app.get('/', (req,res) => {
    if (req.session.authenticated) {
        res.send(`
            <body>
                <p>Hello, ${req.session.name}!</p>
                <button id="members">Go to Members Area</button><br>
                <button id="logout">Logout</button>
            </body>
            <script>
                document.getElementById("members")
                    .addEventListener("click", () => {
                        window.location.href = "/members"
                });

                document.getElementById("logout")
                    .addEventListener("click", () => {
                        window.location.href = "/logout"
                });
            </script>    
        `)
    } else {
        res.send(`
            <body>
                <button id="signup">Sign up</button><br>
                <button id="login">Log in</button>
            </body>
            <script>
                document.getElementById("signup")
                    .addEventListener("click", () => {
                        window.location.href = "/signup"
                });

                document.getElementById("login")
                    .addEventListener("click", () => {
                        window.location.href = "/login"
                });
            </script>
        `);
    }
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

// app.get('/about', (req,res) => {
//     var color = req.query.color;

//     res.send("<h1 style='color:"+color+";'>Patrick Guichon</h1>");
// });

// app.get('/contact', (req,res) => {
//     var missingEmail = req.query.missing;
//     var html = `
//         email address:
//         <form action='/submitEmail' method='post'>
//             <input name='email' type='text' placeholder='email'>
//             <button>Submit</button>
//         </form>
//     `;
//     if (missingEmail) {
//         html += "<br> email is required";
//     }
//     res.send(html);
// });

// app.post('/submitEmail', (req,res) => {
//     var email = req.body.email;
//     if (!email) {
//         res.redirect('/contact?missing=1');
//     }
//     else {
//         res.send("Thanks for subscribing with your email: "+email);
//     }
// });

app.get('/signup', (req,res) => {    
    var html = `
    create user
    <form action='/signupSubmit' method='post'>
    <input name='name' type='text' placeholder='name'><br>
    <input name='email' type='email' placeholder='email'><br>
    <input name='password' type='password' placeholder='password'><br>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.get('/login', (req,res) => {
    var html = `
    log in
    <form action='/loginSubmit' method='post'>
    <input name='email' type='text' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
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

        return res.send(`
            <p>${formatMessage}</p>
            <a href="/signup">Try again</a>
        `);
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);
	
    await userCollection.insertOne({name: name, email: email, password: hashedPassword});
	console.log("Inserted user");
    req.session.authenticated = true; 
    req.session.name = name; 
    req.session.email = email; 
	req.session.cookie.maxAge = expireTime;

    res.redirect('/');
});

app.post('/loginSubmit', async (req,res) => {
    var email = req.body.email;
    var password = req.body.password;

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(email);
	if (validationResult.error != null) {
        console.log(validationResult.error);
        return res.send(`
            <p>Invalid email/password combination.</p>
            <a href="/login">Try again</a>
        `);
	}

    const result = await userCollection.find({email: email}).project({email: 1, password: 1, _id: 1, name: 1}).toArray();

	// console.log(result);
	if (result.length != 1) {
		console.log("user not found");
		res.redirect("/login");
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
        req.session.name = result[0].name;
		req.session.email = email;
		req.session.cookie.maxAge = expireTime;

        res.redirect('/');
		return;
	}
	else {
		console.log("incorrect password");
		res.redirect("/login");
		return;
	}
});

app.get('/members', (req,res) => {
    if (req.session.authenticated) {
        return res.send(`
            <body>
                <h1>Hello, ${req.session.name}.</h1>
                <div id="randomCat"></div>
                <button id="signout">Sign out</button>
            </body>
            <script>
                document.getElementById("signout")
                    .addEventListener("click", () => {
                        window.location.href = "/logout"
                });
    
                const id = Math.floor(Math.random() * 3) + 1;
    
                fetch('/cat/' + id)
                    .then(r => r.text())
                    .then(html => {
                        document.getElementById('randomCat').innerHTML = html;
                });
            </script>            
        `);
    } else {
        return res.redirect("/");
    }
});

app.get('/logout', (req,res) => {
	req.session.destroy();
    res.redirect('/');
});


app.get('/cat/:id', (req,res) => {

    var cat = req.params.id;

    if (cat == 1) {
        res.send("<img src='/fluffy.gif' style='width:250px;'>");
    }
    else if (cat == 2) {
        res.send("<img src='/socks.gif' style='width:250px;'>");
    }
    else if (cat == 3) {
        res.send("<img src='/googlecat.jpg' style='width:250px;'>");
    }
    else {
        res.send("Invalid cat id: "+cat);
    }
});


app.use(express.static(__dirname + "/public"));

app.get(/.*/, (req,res) => {    
	res.status(404);
	res.send("Page not found - 404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 