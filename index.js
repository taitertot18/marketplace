// <!-- Section 2 Group 14 -->
// <!--
// Group Members
// Elijah Aken
// Lily Tait
// Wing Yu Chu
// Caitlyn Stokes --> 
//this is our main connecting javascript so everything connects and runs correctly
const express = require('express');
const app = express();
const path = require('path');
const session = require('express-session');
const port = process.env.PORT || 3000;
const router = express.Router();
const bodyParser = require('body-parser'); // Add this line
const crypto = require('crypto');

const knex = require('knex')({
    client: 'pg',
    connection: {
        host: process.env.RDS_HOSTNAME || 'localhost',
        user: process.env.RDS_USERNAME || 'postgres',
        password: process.env.RDS_PASSWORD || 'tait8248',
        database: process.env.RDS_DB_NAME || 'project3',
        port: process.env.RDS_PORT || 5432,
        ssl: process.env.DB_SSL ? { rejectUnauthorized: false } : false,
    },
});

const secretKey = crypto.randomBytes(32).toString('hex');
console.log('Generated Secret Key:', secretKey);

app.set('view engine', 'ejs');
app.set('views', path.join('views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use('/img', express.static('img'));


app.use(session({
    secret: secretKey,
    resave: false,
    saveUninitialized: true,
}));

app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    res.header('Access-Control-Allow-Headers', 'Content-Type');
    next();
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use(express.urlencoded({ extended: true }));

// Example authenticateUser middleware
const authenticateUser = (req, res, next) => {
    // Check if the user is authenticated
    if (!req.session && !req.session.user) {
      // If not authenticated, redirect to the login page or handle it as needed
      res.redirect('/login');
      return;
    }
  
    // If authenticated, proceed to the next middleware or route handler
    next();
  };

 
  app.get('/logout', (req, res) => {
    try {
        // Log a message indicating that the user has initiated logout
        console.log('User initiating logout');

        // Clear the user property in the session
        req.session.user = null;

        // Log a message indicating that the user has been successfully logged out
        console.log('User successfully logged out');

        // Redirect to the login page or any other desired page after logout
        res.redirect('/login');
    } catch (error) {
        console.error('Error during logout:', error.message);
        res.status(500).send('Internal Server Error');
    }
});

  app.get('/', (req, res) => {
    const user = req.session.user || {}; // Set an empty object if user is undefined
    res.render('index', { user });
});


// Route for displaying item data
app.get('/data', authenticateUser, async (req, res) => {
    try {
        // Query to retrieve item data from the 'items' table
        const query = knex
            .select('item_id', 'item', 'description', 'date_posted', 'item_condition', 'availability', 'user_id', 'email')
            .from('items');

        // Execute the query to get item data
        const itemData = await query;

        // Set editItemId based on the first item in the data array
        const editItemId = itemData.length > 0 ? itemData[0].item_id : null;

        // Fetch authentication data (you might want to adjust this based on your actual authentication data structure)
        const authenticationData = await knex.select('*').from('users');

        // Combine data from both queries into a single object
        const combinedData = {
            itemData,
            editItemId, 
            authenticationData
        };

        // Check if the user is authenticated
        if (!req.session.user) {
            res.redirect('/login');
            return;
        }

        // Render the data.ejs template with the combined data
        res.render('data', combinedData);
    } catch (error) {
        console.error('Error fetching or rendering data:', error.message);
        res.status(500).send(`Internal Server Error: ${error.message}`);
    }
});

app.get("/editpost/edititem/:item_id", async (req, res) => {
    try {
        // Check if the user is authenticated
        if (!req.session.user || !req.session.user.user_id) {
            res.redirect('/login');
            return;
        }

        // Get the user ID from the session
        const userId = req.session.user.user_id;

        // Get the item ID from the route parameters
        const itemId = req.params.item_id;

        // Fetch the specific item data based on the item ID and user ID
        const userItem = await knex
            .select('items.item_id', 'items.item', 'items.description', 'items.email', 'items.date_posted', 'items.item_condition', 'items.availability')
            .from('items')
            .innerJoin('users', 'users.user_id', 'items.user_id')
            .where('users.user_id', userId)
            .andWhere('items.item_id', itemId)
            .first();

        if (!userItem || userItem.length === 0) {
            // Item not found or does not belong to the user
            res.status(404).send('Item not found');
            return;
        }

        // Render the 'edititems.ejs' template with the item data
        res.render("edititems", { userItem: [userItem], user: req.session.user });

    } catch (error) {
        console.error('Error fetching or rendering edit item:', error.message);
        res.status(500).send(`Internal Server Error: ${error.message}`);
    }
});







app.post("/editpost/edititem/:item_id", async (req, res) => {
    try {
        console.log('Received request body:', req.body);  // Add this line for debugging

        // Check if the user is authenticated
        if (!req.session.user || !req.session.user.user_id) {
            res.redirect('/login');
            return;
        }

        // Get the user ID from the session
        const userId = req.session.user.user_id;

        // Get the item ID from the route parameters
        const itemId = req.params.item_id;

        // Retrieve updated information from the request body
        const { item, description, email, date_posted, item_condition, availability } = req.body;

        // Update the item information in the database
        await knex('items')
            .where('user_id', userId)
            .andWhere('item_id', itemId)
            .update({
                item,
                description,
                email,
                date_posted,
                item_condition,
                availability
            });

        // Redirect to the route that displays all the user's posts
        res.redirect('/editpost');

    } catch (error) {
        console.error('Error updating item:', error.message);
        res.status(500).send(`Internal Server Error: ${error.message}`);
    }
});





app.get('/add', (req, res) => {
    // Check if the user is authenticated
    if (!req.session.user) {
        // If not authenticated, redirect to the login page or handle it as needed
        res.redirect('/login');
        return;
    }

    // If authenticated, proceed to render the 'add' page
    res.render('add');
});

const multer = require('multer');

// Assuming you have a 'public' directory to store uploaded images
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'public/uploads');
  },
  filename: function (req, file, cb) {
    // You can customize the file name if needed
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ storage: storage });

// Modify your route to use the 'upload' middleware
app.post('/add', authenticateUser, upload.single('img'), async (req, res) => {
  try {
    // Now you can access the uploaded file using req.file
    const { item, description, date_posted, item_condition, availability, email } = req.body;
    const userId = req.session.user.user_id;
    const img = req.file ? req.file.filename : null; // Check if file was uploaded

    await knex("items").insert({
      item,
      description,
      date_posted,
      item_condition,
      availability,
      email,
      user_id: userId,
    });

    res.redirect("/");
  } catch (error) {
    console.error("Error adding data:", error.message);
    res.status(500).send(`Internal Server Error: ${error.message}`);
  }
});

// Route for rendering login page
app.get('/login', (req, res) => {
    // Get the success message from the session
    const successMessage = req.session.successMessage;
 
    // Clear the success message from the session
    delete req.session.successMessage;
 
    // Render the login view and pass the success message
    res.render('login', { successMessage });
});

// Route for rendering signup page
app.get('/signup', (req, res) => {
    res.render('login', { successMessage: '' }); // Add this line
});

app.get('/login', (req, res) => {
    res.render('login', { user: req.session.user });
  });
// const bcrypt = require('bcryptjs');
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const result = await knex('users').select('*').where({ username });

        if (result.length > 0) {
            const user = result[0];
            const passwordMatch = password === user.password;

            if (passwordMatch) {
                // Set the user in the session
                req.session.user = user;
                res.redirect(`/showdata`);
            } else {
                res.status(401).send('Invalid username/password');
            }
        } else {
            res.status(401).send('Invalid username/password');
        }
    } catch (error) {
        console.error('Error during login:', error.message);
        res.status(500).send('Internal Server Error');
    }
});

// Import the necessary functions from date-fns
const { format } = require('date-fns');

// Define the formatItemsDate function
const formatItemsDate = (items) => {
    return items.map(item => ({
        ...item,
        date_posted: format(new Date(item.date_posted), 'MMMM dd yyyy'),
    }));
};

// Single dynamic route for categories
// Single dynamic route for categories





// In your route handler for the /showdata route
app.get('/showdata', async (req, res) => {
    try {
        const items = await knex.select().from("items");
        const user = req.session.user;
        const requestedUsername = req.params.username || req.query.username || 'defaultUsername';

        // Format the date_posted field to show only Month and Year
        const formattedItems = items.map(item => ({
            ...item,
            date_posted: format(new Date(item.date_posted), 'MMMM dd yyyy'),
        }));

        // Pass the user and requestedUsername variables to the EJS template
        res.render("showdata", { myitems: formattedItems, user: user, requestedUsername: requestedUsername });
    } catch (error) {
        console.error(error);
        res.status(500).send("Internal Server Error");
    }
});




app.get('/category/:category', async (req, res) => {
    try {
        const { category } = req.params;
        const user = req.session.user;

        // Query the database for items with the specified category
        const items = await knex.select("*").from("items").where("item", category);
        
        // Check if items were found for the specified category
        if (items.length === 0) {
            // Handle case where no items were found for the category
            return res.status(404).send('No items found for the specified category');
        }

        // Format the date_posted field to show only Month and Year
        const formattedItems = items.map(item => ({
            ...item,
            date_posted: format(new Date(item.date_posted), 'MMMM dd yyyy'),
        }));

        // Render the category.ejs template with the retrieved items
        res.render("category", { category, myitems: formattedItems, user: user });
    } catch (error) {
        console.error(error);
        res.status(500).send("Internal Server Error");
    }
});



// Assuming you have the express and express-session middleware set up

// Logout route
// Logout route







// Example of how to use the authenticateUser middleware in other routes
app.get('/dashboard', authenticateUser, (req, res) => {
    // Render the dashboard for authenticated users
    res.render('dashboard');
});

// Add other routes as needed




app.post('/signup', async (req, res) => {
    const { first_name, last_name, username, password, email } = req.body;

    try 
        {
            // Check if the username contains "admin" (case-insensitive)
            if (username.toLowerCase().includes('admin')) {
                return res.status(400).send('Username cannot contain "admin".');
            }
        // Use bcrypt to hash the password
        const existingUser = await knex('users')
            .select('username', 'email')
            .where('username', username)
            .orWhere('email', email)
            .first();

        if (existingUser) {
            const duplicatedFields = [];
            if (existingUser.username === username) duplicatedFields.push('Username');
            if (existingUser.email === email) duplicatedFields.push('Email');

            const errorMessage = `The following fields are already taken: ${duplicatedFields.join(', ')}`;
            return res.status(400).send(errorMessage);
        }

        await knex('users').insert({
            first_name,
            last_name,
            username,
            password, // Store hashed password
            email,
            usertype: 'USER',
        });

        req.session.successMessage = `Account created for ${username}.`;
 
        // Redirect to login page
        res.redirect('/login');
     } catch (error) {
        console.error('Error during signup:', error.message);
        res.status(500).send('Internal Server Error');
     }
});



      
      
    app.get("/user/edituser/:username", (req, res) => {      
        const username = req.params.username;
        
        // Check if the user is authenticated
        if (!req.session.user) {
            // Redirect to the login page or handle as needed
            res.redirect('/login');
            return;
        }
    
        const user = req.session.user;
    
        knex.select("username", "first_name", "last_name", "email", "password")
            .from('users')
            .where("username", username)
            .then(users => {
                res.render("edituser", { myusers: users, user: user });
            })
            .catch(err => {
                console.log(err);
                res.status(500).json({ err });
            });    
    });
    
      
     // Assuming 'userItems' is an array containing user-specific item data
     // app.get('/category/:categoryid/:itemid', async (req, res) => {
        app.get('/category/:user_id', async (req, res) => {
            try {
                const userItems = await knex
                    .select('item_id', 'item', 'description', 'date_posted', 'item_condition', 'availability', 'user_id', 'email')
                    .from('items')
                    .where('user_id', req.params.user_id);
        
                // Fetch the user information based on user_id
                const user = await knex
                    .select('user_id', 'username', 'email', 'usertype') // Adjust these fields based on your user data structure
                    .from('users')
                    .where('user_id', req.params.user_id)
                    .first();
        
                res.render('postlist', { user, userItems });
            } catch (error) {
                console.error('Error fetching or rendering data:', error.message);
                res.status(500).send(`Internal Server Error: ${error.message}`);
            }
        });
        

// Update user information
// Update user information
app.post("/category/:user_id", async (req, res) => {
    try {
        const updatedUserInfo = {
            first_name: req.body.first_name,
            last_name: req.body.last_name,
            email: req.body.email,
            password: req.body.password
        };

        const result = await knex("users")
            .where("user_id", req.params.user_id) // Corrected from req.params.username
            .update(updatedUserInfo);

        if (result === 1) {
            // The update was successful
            // Redirect logic based on user type (admin or regular user)
            const isAdmin = req.session.user && req.session.user.username.toLowerCase().includes('admin');
            if (isAdmin) {
                res.redirect('/admin'); // Redirect to admin page
            } else {
                res.redirect(`/category/${req.params.user_id}`); // Redirect to user's page
            }
        } else {
            res.status(404).json({ error: "User not found" });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});


app.get("/editpost/edititem/:item_id", async (req, res) => {
    try {
        // Check if the user is authenticated
        if (!req.session.user || !req.session.user.user_id) {
            res.redirect('/login');
            return;
        }

        // Get the user ID from the session
        const userId = req.session.user.user_id;

        // Get the item ID from the route parameters
        const itemId = req.params.item_id;

        // Fetch the specific item data based on the item ID and user ID
        const item = await knex
            .select('items.item', 'items.description', 'items.email', 'items.date_posted', 'items.item_condition', 'items.availability')
            .from('items')
            .innerJoin('users', 'users.user_id', 'items.user_id')
            .where('users.user_id', userId)
            .andWhere('items.item_id', itemId)
            .first(); // Use first() to get only one result

        if (!item) {
            // Item not found or does not belong to the user
            res.status(404).send('Item not found');
            return;
        }

        // Render the 'edititems.ejs' template with the item data
        res.render("edititems", { item, user: req.session.user });
    } catch (error) {
        console.error('Error fetching or rendering edit item:', error.message);
        res.status(500).send(`Internal Server Error: ${error.message}`);
    }
});

app.post("/editpost/edititem/:item_id", async (req, res) => {
    try {
        // Check if the user is authenticated
        if (!req.session.user || !req.session.user.user_id) {
            res.redirect('/login');
            return;
        }

        // Get the user ID from the session
        const userId = req.session.user.user_id;

        // Get the item ID from the route parameters
        const itemId = req.params.item_id;

        // Retrieve updated information from the request body
        const { item, description, email, date_posted, item_condition, availability } = req.body;

        // Update the item information in the database
        await knex('items')
            .where('user_id', userId)
            .andWhere('item_id', itemId)
            .update({
                item,
                description,
                email,
                date_posted,
                item_condition,
                availability
            });

        // Redirect to the route that displays all the user's posts
        res.redirect('/edititems');

    } catch (error) {
        console.error('Error updating item:', error.message);
        res.status(500).send(`Internal Server Error: ${error.message}`);
    }
});
 
app.post("/user/edituser/:username", async (req, res) => {
         try {
             const updatedUserInfo = {
                 first_name: req.body.first_name,
                 last_name: req.body.last_name,
                 email: req.body.email,
                 password: req.body.password
             };
            

      
             const result = await knex("users")
                 .where("username", req.params.username)
                 .update(updatedUserInfo);
      
             if (result === 1) {
                 // The update was successful (1 row updated)
      
                 // Check if the logged-in user is an admin (username contains "admin" case-insensitive)
                 const isAdmin = req.session.user && req.session.user.username.toLowerCase().includes('admin');
      
                 if (isAdmin) {
                     // If the logged-in user is an admin, redirect to the admin page
                     res.redirect('/admin'); // Change '/admin' to the actual admin page route
                 } else {
                     // If the logged-in user is a regular user, redirect to their page
                     res.redirect(`/${req.params.username}`);
                 }
             } else {
                 // No rows were updated, indicating that the username wasn't found
                 res.status(404).json({ error: "User not found" });
             }
         } catch (err) {
             console.error(err);
             res.status(500).json({ error: "Internal Server Error" });
         }
     });
      
      
     app.use(express.static(path.join(__dirname, 'public')));

    
// Route for displaying items posted by the logged-in user
app.get('/userItems', authenticateUser, async (req, res) => {
    try {
      // Check if the user is authenticated
      if (!req.session.user) {
        res.redirect('/login');
        return;
      }
  
      // Retrieve items posted by the logged-in user
      const userId = req.session.user.user_id;
      const userItems = await knex
        .select()
        .from('items')
        .where({ user_id: userId });
  
      // Render the userItems.ejs template with the retrieved items
      res.render('userItems', { userItems });
    } catch (error) {
      console.error('Error fetching or rendering user items:', error.message);
      res.status(500).send(`Internal Server Error: ${error.message}`);
    }
  });

// Start the server
app.listen(port, () => console.log(`Server is running on port ${port}`));

app.post('/user/deleteuser/:username', async (req, res) => {
    try {
        const usernameToDelete = req.params.username;
 
        // Perform the deletion in your database
        const result = await knex('users')
            .where('username', usernameToDelete)
            .del();
 
        if (result === 1) {
            // Successful deletion (1 row deleted)
 
            // Check if the logged-in user is an admin (username contains "admin" case-insensitive)
            const isAdmin = req.session.user && req.session.user.username.toLowerCase().includes('admin');
 
            if (isAdmin) {
                // If the logged-in user is an admin, redirect to the admin page
                res.redirect('/admin'); // Change '/admin' to the actual admin page route
            } else {
                // If the logged-in user is a regular user, redirect to their page
                res.redirect('/');
            }
        } else {
            // No rows were deleted, indicating that the username wasn't found
            res.status(404).json({ error: 'User not found' });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/editpost', authenticateUser, async (req, res) => {
    try {
        // Check if the user is authenticated
        if (!req.session.user || !req.session.user.user_id) {
            res.redirect('/login');
            return;
        }

        // Get the user ID from the session
        const userId = req.session.user.user_id;

        // Fetch user-specific item data based on the user ID
        const userItems = await knex
            .select('items.item_id', 'items.item', 'items.description', 'items.date_posted', 'items.item_condition', 'items.availability', 'users.user_id', 'users.email')
            .from('items')
            .innerJoin('users', 'users.user_id', 'items.user_id')
            .where('users.user_id', userId);

        // Render the 'postlist.ejs' template with the userItems data
        res.render('postlist', { user: req.session.user, userItems: userItems });
    } catch (error) {
        console.error('Error fetching or rendering user items for edit:', error.message);
        res.status(500).send(`Internal Server Error: ${error.message}`);
    }
});




  // Route in index.js
  app.get("/:username", async (req, res) => {
    const requestedUsername = req.params.username;

    try {
        // Fetch user-specific data based on the requested username
        const users = await knex.select("username", "first_name", "last_name", "email", "password")
            .from('users')
            .where("username", requestedUsername);

        // Check if the requested username contains "admin"
        if (requestedUsername.toLowerCase().includes('admin')) {
            // If it contains "admin", retrieve all users' data
            const allUsers = await knex.select("username", "first_name", "last_name", "email", "password")
                .from('users');

            res.render("user", { myusers: allUsers, requestedUsername: requestedUsername, user: users[0] });
        } else {
            // For regular users, only retrieve their own data
            res.render("user", { myusers: users, requestedUsername: requestedUsername, user: users[0] });
        }
    } catch (err) {
        console.log(err);
        res.status(500).json({ err });
    }
});



app.post('/editpost/deleteitem/:item_id', async (req, res) => {
    try {
        // Check if the user is authenticated
        if (!req.session.user || !req.session.user.user_id) {
            res.redirect('/login');
            return;
        }

        // Get the user ID from the session
        const userId = req.session.user.user_id;

        // Get the item ID from the route parameters
        const itemId = req.params.item_id;

        // Perform the deletion in your database
        const result = await knex('items')
            .where('user_id', userId)
            .andWhere('item_id', itemId)
            .del();

        if (result === 1) {
            // Successful deletion (1 row deleted)
            res.redirect('/editpost'); // Redirect to the editpost page after successful deletion
        } else {
            // No rows were deleted, indicating that the item wasn't found or doesn't belong to the user
            res.status(404).send('Item not found');
        }
    } catch (err) {
        console.error(err);
        res.status(500).send('Internal Server Error');
    }
});





