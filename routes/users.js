// importing express from express dependency installed in package.json
import express from "express";
// importing functions from controller
import controller from "../controller/users.js";
// importing create token from middleware
import { createToken } from "../middleware/AuthenticateUser.js";

// grouping together functions with similar routes
const router = express.Router()
router
    .route('/')
        .get(controller.getManyUsers)
        .post(controller.addOneUser)

router
    .route('/:userID')
        .get(controller.getOneUser)
        .patch(controller.editOneUser)
        .delete(controller.deleteOneUser);
router  
    .route('/login',createToken)
    .post(controller.logInUser)

    // exporting globally
export default router