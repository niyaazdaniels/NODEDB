// Importing the Express module from the installed express package
import express from "express";
// Importing functions from the users controller
import controller from "../controller/users.js";


// Creating an instance of the Express Router
const router = express.Router();

router 
    .route('/')
    .post(controller.registerOneUser)

// Exporting the router to be used globally
export default router;
