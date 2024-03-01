// Importing the Express module from the installed express package
import express from "express";
// Importing functions from the users controller
import controller from "../controller/users.js";


// Creating an instance of the Express Router
const router = express.Router();

// Grouping together routes with similar paths
router
    .route('/')
        .get(controller.getManyUsers) // GET request to fetch many users
        .post(controller.addOneUser); // POST request to add a new user

router
    .route('/:userID')
        .get(controller.getOneUser) // GET request to fetch a single user by ID
        .patch(controller.editOneUser) // PATCH request to edit a user by ID
        .delete(controller.deleteOneUser); // DELETE request to delete a user by ID

// Exporting the router to be used globally
export default router;
