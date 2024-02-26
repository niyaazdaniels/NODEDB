// importing database from config
import {pool} from '../config/config.js'

// retrieve all users
const getUsers = async () => {
    const [result] = await pool.query
    (`SELECT * 
    FROM users`);
    return result
};
// retrieve a single user
const getUser = async (userID) => {
    const [result] = await pool.query
    (`SELECT * 
    FROM users
    WHERE userID = ?`,[userID]);
    return result
};
// adding new user 
const addUser = async (firstName, lastName, userAge, gender, userRole, emailAdd, userPass, userProfile) => {
    const [user] = await pool.query (`
    INSERT INTO users (firstName, lastName, userAge, gender, userRole, emailAdd, userPass, userProfile) VALUES(?,?,?,?,?,?,?,?)`,
    [firstName, lastName, userAge, gender, userRole, emailAdd, userPass, userProfile]);
    return getUser(user.insertId);
};
// editing individual user
const editUser = async (firstName,lastName,userAge,gender,userRole,emailAdd,userPass,userProfile,userID)=>{
    const [user] = await pool.query(`
    UPDATE users 
    SET firstName = ?,lastName = ?,userAge = ?,gender = ?,userRole = ?,emailAdd = ?,userPass = ?,userProfile = ?
     WHERE userID = ?
    `,[firstName,lastName,userAge,gender,userRole,emailAdd,userPass,userProfile,userID])
    return getUsers(user)
};
// deleting individual user
const deleteUser = async (userID) => {
    const [user] = await pool.query(`
    DELETE FROM users
    WHERE userID = ?
    `,[userID]);
    return getUsers(user)
};
// verifying a user on login
const verifyUser = async (emailAdd) => {
    const [[{userPass}]] = await pool.query(`
    SELECT userPass FROM users WHERE emailAdd = ?
    `,[emailAdd]);
    return userPass
}

// exporting functions by making them global
export {getUsers,getUser,addUser,editUser,deleteUser,verifyUser};

