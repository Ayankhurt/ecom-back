import 'dotenv/config'
import express from 'express';
import { db } from './db.mjs';
import cors from 'cors';
import bcrypt from "bcryptjs";
import { customAlphabet } from 'nanoid';
import jwt from 'jsonwebtoken';

const app = express();

const SECRET = process.env.SECRET_TOKEN;

app.use(express.json());

const allowedOrigins = [
  'https://ecom-front-gamma.vercel.app/signup',
  'https://ecom-front-gamma.vercel.app/login',
  'https://ecom-front-gamma.vercel.app'
];

app.use(cors({
  origin: function(origin, callback){
    if(!origin) return callback(null, true);
    if(allowedOrigins.indexOf(origin) === -1){
      const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  credentials: true
}));

app.get('/' , async(req , res) => {
    try {
        let result = await db.query('SELECT * FROM users')
        res.status(200).send({message: "Success" , data: result.rows, result: result})
    } catch (error) {
        res.status(500).send({message: "Internal Server Error"})
    }
});

app.post('/sign-up' , async(req, res) => {
    let reqBody = req.body;
    if(!reqBody.firstName || !reqBody.lastName || !reqBody.email || !reqBody.password){
        res.status(400).send({message: "required parameter missing"})
        return;
    }
    reqBody.email = reqBody.email.toLowerCase();
    let query = `SELECT * FROM users WHERE email = $1`
    let values = [reqBody.email]
    try {
        let result = await db.query(query , values)
        if(result.rows?.length){
            res.status(400).send({message: "User Already Exist With This Email"});
            return;
        }
        let addQuery = `INSERT INTO users(first_name, last_name, email, password) VALUES ($1, $2, $3, $4)`
        const salt = bcrypt.genSaltSync(10);
        const hash = bcrypt.hashSync(reqBody.password, salt);
        let addValues = [reqBody.firstName , reqBody.lastName, reqBody.email, hash]
        let addUser = await db.query(addQuery , addValues);
        res.status(201).send({message: "User Created"})
    } catch (error) {
        console.log("ERROR" , error);
        res.status(500).send({message: "Internal Server Error"})
    }
})

app.post('/login' , async(req , res) => {
    let reqBody = req.body;
    if(!reqBody.email || !reqBody.password){
        res.status(400).send({message: "Required Parameter Missing"})
        return;
    }
    reqBody.email = reqBody.email.toLowerCase();
    let query = `SELECT * FROM users WHERE email = $1`;
    let values = [reqBody.email];

    try {
        let result = await db.query(query, values);
        if(!result.rows.length){
            res.status(400).send({message: "User Doesn't exist with this Email"});
            return;
        }
        let isMatched = await bcrypt.compare(reqBody.password, result.rows[0].password);

        if(!isMatched){
            res.status(401).send({message: "Password did not Matched"});
            return;
        }

        let token = jwt.sign({
            id: result.rows[0].user_id,
            firstName: result.rows[0].first_name,
            last_name: result.rows[0].last_name,
            email: result.rows[0].email,
            user_role: result.rows[0].user_role,
            iat: Date.now() / 1000,
            exp: (Date.now() / 1000) + (1000*60*60*24)
        }, SECRET);

        res.cookie('Token', token, {
            maxAge: 86400000,
            httpOnly: true,
            secure: true
        });
        res.status(200).send({message: "User Logged in" , user: {
            user_id: result.rows[0].user_id,
            first_name: result.rows[0].first_name,
            last_name: result.rows[0].last_name,
            email: result.rows[0].email,
            phone: result.rows[0].phone,
            user_role: result.rows[0].user_role,
            profile: result.rows[0].profile,
        }})
    } catch (error) {
        console.log("Error", error)
        res.status(500).send({message: "Internal Server Error"})
    }
})

// Remove app.listen for Vercel serverless deployment
export default app;
