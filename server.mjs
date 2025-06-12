import express from "express";
import cors from "cors";
import db from "./db.mjs";
import bcrypt from "bcrypt";
import { customAlphabet } from 'nanoid'

const PORT = process.env.PORT || 3000;
const app = express();

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
app.post("/login", async (req, res) => {
  let reqbody = req.body;
  if (!reqbody.email || !reqbody.password) {
    res.status(400).send({ message: "All fields are required" });
    return;
  }
  let query = `SELECT * FROM users WHERE email = $1`;
  let values = [reqbody.email];

  try {
    let result = await db.query(query, values);
    if (!result.rows?.length) {
      res.status(400).send({ message: "user does not exist with this email" });
    }
  } catch (error) {
    res.status(500).send({ message: "Error logging in", error: error.message });
  }
})

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
