import 'dotenv/config';
import express from "express";
import cors from "cors";
import db from "./db.mjs";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { customAlphabet } from 'nanoid'

const SECRET = process.env.SECRET_TOKEN;
const PORT = process.env.PORT || 3000;

const app = express();
/// new ///
app.use(express.json());
app.use(cors());

app.get("/", async (req, res) => {
  // res.send("Hello World");
  try {
    let result = await db.query("SELECT * FROM users");
    res.status(200).send({ message: "Data fetched successfully", data: result.rows });
  } catch (error) {
    res.status(500).send({ message: "Error fetching data", error: error.message });
  }
});

app.post("/sign-up", async (req, res) => {
  let reqbody = req.body;
  if (!reqbody.firstName || !reqbody.lastName || !reqbody.email || !reqbody.password) {
    res.status(400).send({ message: "All fields are required" });
    return;
  }

  reqbody.email = reqbody.email.toLowerCase();
  let query = `SELECT * FROM users WHERE email = $1`;
  let values = [reqbody.email];

  try {
    let result = await db.query(query, values);
    if (result.rows?.length) {
      res.status(400).send({ message: "Email already exists" });
      return;
    }
    let addQuery = `INSERT INTO users (first_name, last_name, email, password) VALUES ($1, $2, $3, $4) RETURNING *`;
    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(reqbody.password, salt);
    let addValues = [reqbody.firstName, reqbody.lastName, reqbody.email, hash];
    let addUser = await db.query(addQuery, addValues);
    res.status(201).send({ message: "User created successfully", data: result.rows[0] });
  } catch (error) {
    res.status(500).send({ message: "Error creating user", error: error.message });
  };
})
app.post('/login', async (req, res) => {
  let reqBody = req.body;
  if (!reqBody.email || !reqBody.password) {
    res.status(400).send({ message: "Required Parameter Missing" })
    return;
  }
  reqBody.email = reqBody.email.toLowerCase();
  let query = `SELECT * FROM users WHERE email = $1`;
  let values = [reqBody.email];

  try {
    let result = await db.query(query, values);
    if (!result.rows.length) {
      res.status(400).send({ message: "User Doesn't exist with this Email" });
      return;
    }

    let isMatched = await bcrypt.compare(reqBody.password, result.rows[0].password); // true

    if (!isMatched) {
      res.status(401).send({ message: "Password did not Matched" });
      return;
    }

    let token = jwt.sign({
      id: result.rows[0].user_id,
      firstName: result.rows[0].first_name,
      last_name: result.rows[0].last_name,
      email: result.rows[0].email,
      user_role: result.rows[0].user_role,
      iat: Date.now() / 1000,
      exp: (Date.now() / 1000) + (1000 * 60 * 60 * 24)
    }, SECRET);
    res.cookie('Token', token, {
      maxAge: 86400000,
      httpOnly: true,
      secure: true
    });
    res.status(200)
    res.send({
      message: "User Logged in", token, user: {
        user_id: result.rows[0].user_id,
        first_name: result.rows[0].first_name,
        last_name: result.rows[0].last_name,
        email: result.rows[0].email,
        phone: result.rows[0].phone,
        user_role: result.rows[0].user_role,
        profile: result.rows[0].profile,
      }
    })


  } catch (error) {
    console.log("Error", error)
    res.status(500).send({ message: "Internal Server Error" })
  }
})

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
