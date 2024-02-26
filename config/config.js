// importing mysql dependencies from package.json
import mysql from 'mysql2';
// importing config function from dotenv in package.json
import {config} from 'dotenv';
config();


// fetching database
const pool = mysql.createPool({
    host: process.env.MYSQL_ADDON_HOST,
    database: process.env.MYSQL_ADDON_DB,
    user: process.env.MYSQL_ADDON_USER,
    password: process.env.MYSQL_ADDON_PASSWORD
}).promise();
// exporting database 
export {pool}