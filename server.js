import express from "express";
import {config} from "dotenv";
import cors from 'cors';
import productsRouter from "./routes/products.js";
import usersRouter from "./routes/users.js"
import cookieParser from 'cookie-parser';
import { verifyToken, createToken } from "./middleware/AuthenticateUser.js";
config();

const PORT = process.env.MYSQL_ADDON_PORT || 7070

const app = express()

app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use('/products',productsRouter); //place verify token here
app.use('/users',usersRouter);
app.use('/login', usersRouter);
app.use(cookieParser());

app.listen(PORT, () => console.log(`Server is running on PORT http://localhost:${PORT}`));