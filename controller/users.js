import {getUsers,getUser,addUser,editUser,deleteUser, verifyUser} from '../models/users.js';
// importing bcrypt for password hashing when a new user is added
import bcrypt from 'bcrypt';

export default {
    // controller to get all users from the database
    getManyUsers: async (req, res) => {
        try {
            const users = await getUsers();
            if (!users) {
                throw new Error("No users found!");
            }
            res.send(users);
        } catch (error) {
            console.error("Error in fetching all the users:", error);
            res.status(500).send({ error: "Internal Server Error" });
        }
    },    
    // controller to add a single user from the database
    addOneUser: async (req, res) => {
        try {
            const { firstName, lastName, userAge, gender, userRole, emailAdd, userPass, userProfile } = req.body;
            bcrypt.hash(userPass, 10, async (err,hash)=> {
            if (err) throw err;
            await addUser(firstName, lastName, userAge, gender, userRole, emailAdd, hash, userProfile);
            })
            res.send('User has been added successfully');
            } catch (error) {
            res.status(500).send('Error registering user: ' + error);
         }
    },    
    // controller to get a single user from the database
    getOneUser: async (req, res) => {
        try {
            const userId = +req.params.userID;
            const user = await getUser(userId);
            if (user) {
                res.send(user);
            } else {
                res.status(404).send({ error: "User not found" });
            }
        } catch (error) {
            res.status(500).send({ error: "Internal Server Error" });
        }
    },    
    // controller to edit an individual user that exists within the database
    editOneUser: async (req, res) => {
        try {
            const [user] = await getUser(+req.params.userID);
            let { firstName, lastName, userAge, gender, userRole, emailAdd, userPass, userProfile } = req.body;
            
            firstName = firstName || user.firstName;
            lastName = lastName || user.lastName;
            userAge = userAge || user.userAge;
            gender = gender || user.gender;
            userRole = userRole || user.userRole;
            emailAdd = emailAdd || user.emailAdd;
            userPass = userPass || user.userPass;
            userProfile = userProfile || user.userProfile;
            
            await editUser(firstName, lastName, userAge, gender, userRole, emailAdd, userPass, userProfile, +req.params.userID);
            
            res.json(await getUsers());
        } catch (error) {
            res.status(500).json({ error: 'An error occurred while editing the user.' });
        }
    },    
    // controller to delete a single user from the database
    deleteOneUser: async (req, res) => {
        try {
            const userId = +req.params.userID;
            const deletedUser = await deleteUser(userId);
            if (deletedUser) {
                res.send({ message: "User deleted successfully" });
            } else {
                res.status(404).send({ error: "User not found" });
            }
        } catch (error) {
            res.status(500).send({ error: "Internal Server Error" });
        }
    },    
    // controller to login a user that ALREADY exists within the database by checking whether the passwords match
    logInUser: async(req, res, next) => {
        const {emailAdd, userPass} = req.body;
        const hashedPassword = await verifyUser(emailAdd);
        bcrypt.compare(userPass,hashedPassword,(err, result) => {
            if (err) throw err;
            if (result === true){
                next();
            }else {
                res.send({msg : "Password does not match, please try again."})
            }
        })
    }
}

