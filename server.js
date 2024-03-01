// Importing required modules and packages
import express from "express";
import { config } from "dotenv";
import cors from 'cors';
import productsRouter from "./routes/products.js";
import usersRouter from "./routes/users.js";
import loginRouter from "./routes/login.js"
import signUpRouter from "./routes/signup.js"
import cookieParser from 'cookie-parser';
import { verifyToken, createToken } from "./middleware/AuthenticateUser.js";

// Load environment variables from .env file
config();

// Set the port for the server to listen on
const PORT = process.env.MYSQL_ADDON_PORT || 7070;

// Create an instance of Express application
const app = express();
// Middleware for enabling CORS
app.use(cors());
// Middleware for parsing JSON body
app.use(express.json());
// Middleware for serving static files from the 'public' directory
app.use(cookieParser());
app.use(express.static('public'));
// Routes for products and users
app.use('/products', productsRouter); // Middleware for verifying token
app.use('/users', usersRouter);
app.use('/login', createToken, loginRouter); 
app.use('/signup', signUpRouter); 
// Middleware for parsing cookies
 
// Start the server and listen on the defined port
app.listen(PORT, () => console.log(`Server is running on PORT http://localhost:${PORT}`));
