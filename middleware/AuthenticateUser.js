// importing mysql dependencies from package.json

import {config} from 'dotenv'
config()
// importing jwt dependency from package.json
import jwt from 'jsonwebtoken';
// importing hasing functionality from package.json
import bcrypt from 'bcrypt';
// importing the verify from models MVC
import { verifyUser } from '../models/users.js';


// middleware for login only, checks if a token is present or valid 
const verifyToken = (req, res, next) => { 
    let { cookie } = req.headers;
    let tokenInHeader = cookie && cookie.split('=')[1];
    if (!tokenInHeader) {
        return res.sendStatus(401); // If No Token found in website headers
    }
    jwt.verify(tokenInHeader, process.env.SECRET_KEY, (err, user) => { 
        if (err) {
            return res.status(401).send({ msg: "Invalid or expired token" });
        }
        req.user = user; 
        next();
    });
};

//login and generates a new token for the user upon log in
const createToken = async (req, res, next) => {
        const {emailAdd, userPass} = req.body 
        const hashedUserPass = await verifyUser(emailAdd) 
        bcrypt.compare(userPass,hashedUserPass,(err,result) =>{    
            if (err) throw err 
            if(result === true){
                const token = jwt.sign({emailAdd:emailAdd}, process.env.SECRET_KEY,{expiresIn:'1hr'})
                res.cookie('jwt', token, {httpOnly:false})  
                res.send({
                    token:token,
                    msg: "You have logged in successfully!"})
                next()
            }else {
                res.send({msg: "The username or password does not match"})
            }
        })
    }
    // exporting functions and making it global
    export {verifyToken, createToken}
