// importing express from express dependency installed in package.json
import express from "express";
// importing functions from controller
import controller from "../controller/products.js";
// importing verify token from middleware
import { verifyToken } from "../middleware/AuthenticateUser.js";

// grouping together functions with similar paths
const router = express.Router()
router 
    .route('/')  
        .get(controller.getManyProducts)  
        .post(controller.addOneProduct)
       
router
    .route('/:prodID')
        .get(controller.getOneProduct)
        .patch(controller.editOneProduct)
        .delete(controller.deleteOneProduct)
    
        // making global
export default router 