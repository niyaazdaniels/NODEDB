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
const verifyToken = async (req,res,next)=>{
    const {emailAdd,userPass} = req.body
    const hashedPassword = await verifyUser(emailAdd)
    bcrypt.compare(userPass,hashedPassword,(err,result)=>{
        if(err) throw err
        if(result === true){
            console.log(emailAdd)
            const token = jwt.sign({emailAdd:emailAdd},process.env.SECRET_KEY,{expiresIn:'1h'})
            res.send({
                token:token,
                msg:'You have login succesfully'
            })
            next()
        }else{
            res.json({msg:'Password or Email address doesnt match'})
        }
    })
}

//login and generates a new token for the user upon log in
const createToken = async (req, res, next) => {
    try {
        const { emailAdd, userPass } = req.body;
        const hashedUserPass = await verifyUser(emailAdd);

        if (!hashedUserPass) {
            console.log("User not found");
            return res.status(401).send({ msg: "User not found" });
        }

        const result = await bcrypt.compare(userPass, hashedUserPass);

        if (result === true) {
            console.log("Password matched. Creating token...");
            const token = jwt.sign({ emailAdd: emailAdd }, process.env.SECRET_KEY, { expiresIn: '1h' });
            res.cookie('jwt', token, { httpOnly: false });
            console.log("Token created successfully");
            // Do not send a response here
            next(); // Proceed to the next middleware
        } else {
            console.log("Password does not match");
            return res.status(401).send({ msg: "The username or password does not match" });
        }
    } catch (error) {
        console.error("Error logging in:", error);
        return res.status(500).send('Error logging in: ' + error);
    }
};
    // exporting functions and making it global
    export {verifyToken, createToken}
