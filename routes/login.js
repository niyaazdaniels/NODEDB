// Importing the Express module from the installed express package
import express from "express";
// Importing functions from the users controller
import controller from "../controller/users.js";
// Importing createToken function from the authentication middleware
import { verifyToken , createToken } from "../middleware/AuthenticateUser.js";

// Creating an instance of the Express Router
const router = express.Router();
router  
    .route('/') // Route for user login with token creation middleware
    .post(controller.logInUser); // POST request to log in a user

// Exporting the router to be used globally
export default router;
