// Importing the database pool from the config file
import { pool } from '../config/config.js';

// Retrieve all users from the database
const getUsers = async () => {
    const [result] = await pool.query(`
        SELECT * 
        FROM users`);
    return result;
};

// Retrieve a single user by userID from the database
const getUser = async (userID) => {
    const [result] = await pool.query(`
        SELECT * 
        FROM users
        WHERE userID = ?`, [userID]);
    return result;
};
// Add a new user to the database
const addUser = async (firstName, lastName, userAge, gender, userRole, emailAdd, userPass, userProfile) => {
    const [user] = await pool.query(`
        INSERT INTO users (firstName, lastName, userAge, gender, userRole, emailAdd, userPass, userProfile) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [firstName, lastName, userAge, gender, userRole, emailAdd, userPass, userProfile]);
    return getUser(user.insertId);
};
// Edit an individual user in the database
const editUser = async (firstName, lastName, userAge, gender, userRole, emailAdd, userPass, userProfile, userID) => {
    const [user] = await pool.query(`
        UPDATE users 
        SET firstName = ?, lastName = ?, userAge = ?, gender = ?, userRole = ?, emailAdd = ?, userPass = ?, userProfile = ?
        WHERE userID = ?`,
        [firstName, lastName, userAge, gender, userRole, emailAdd, userPass, userProfile, userID]);
    return getUsers(user);
};
// Delete an individual user from the database
const deleteUser = async (userID) => {
    const [user] = await pool.query(`
        DELETE FROM users
        WHERE userID = ?`,
        [userID]);
    return getUsers(user);
};
// Verify a user on login by retrieving their password from the database
const verifyUser = async (emailAdd) => {
    try {
        const [[{ userPass }]] = await pool.query(`
            SELECT userPass FROM users WHERE emailAdd = ?`,
            [emailAdd]);
        return userPass;
    } catch (error) {
        // Handle errors, e.g., user not found
        throw new Error('User not found');
    }
};
const registerUser = async (emailAdd, userPass) => {
    await pool.query(`
    INSERT INTO users (emailAdd, userPass) 
    VALUES (?, ?)
    `,[emailAdd, userPass])
}

// Exporting functions to make them globally accessible
export { getUsers, getUser, addUser, editUser, deleteUser, verifyUser, registerUser };
