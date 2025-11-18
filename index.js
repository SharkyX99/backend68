// server.js
require("dotenv").config(); // โหลดค่าจาก .env

const express = require("express");
const mysql = require("mysql2/promise");
const cors = require("cors");
const app = express();
//HAsh password

const bcrypt = require("bcrypt");

app.use(express.json());
app.use(cors());

// ค่า prot

// เรียกใช้ json webtoken
const jwt = require("jsonwebtoken");
const SECRET_KEY = process.env.JWT_SECRET;
///
const db = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
});

// Route ทดสอบการเชื่อมต่อ
app.get("/ping", async (req, res) => {
  try {
    const [rows] = await db.query("SELECT NOW() AS now");
    res.json({ status: "ok", time: rows[0].now });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});

//funtion veryfly
function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Token not provided" });
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    next(); // ผ่านการตรวจสอบแล้วไปต่อ
  } catch (err) {
    return res.status(403).json({ message: "Invalid or expired token" });
  }
}
// GET users
app.get("/users", verifyToken, async (req, res) => {
  try {
    const [rows] = await db.query(
      "SELECT id, firstname, fullname, lastname FROM tbl_users"
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: "Query failed" });
  }
});
// GET /users/:id - ดึงข้อมูลผู้ใช้ตาม id
app.get("/users/:id", verifyToken, async (req, res, next) => {
  const { id } = req.params;
  try {
    const [rows] = await db.query("SELECT * FROM tbl_users WHERE id = ?", [id]);
    if (rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json(rows[0]);
  } catch (err) {
    next(err);
  }
});

// DELEAT /users/:id - ดึงข้อมูลผู้ใช้ตาม id
app.delete("/users/:id", async (req, res, next) => {
  const { id } = req.params;
  try {
    const [rows] = await db.query("DELETE FROM tbl_users WHERE id = ?", [id]);
    if (rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json(rows[0]);
  } catch (err) {
    next(err);
  }
});
// POST /users - เพิ่มผู้ใช้ใหม่
app.post("/users", async (req, res) => {
  const { firstname, fullname, lastname, username, password, status } =
    req.body;
  try {
    if (!password)
      return res.status(400).json({ error: "Password is required" });
    const hashedPassword = await bcrypt.hash(password, 10);

    const [result] = await db.query(
      "INSERT INTO tbl_users (firstname, fullname, lastname,username, password, status) VALUES (?, ?, ?,?, ?, ?)",
      [firstname, fullname, lastname, username, hashedPassword, status]
    );
    res.json({
      id: result.insertId,
      firstname,
      fullname,
      lastname,
      username,
      password,
      status,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Insert failed" });
  }
});

// เริ่มเซิร์ฟเวอร์
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`Server running on http://localhost:${PORT}`)
);

//PUT /users/:id - แก้ไขข้อมูลผู้ใช้
app.put("/users/:id", async (req, res) => {
  const { id } = req.params;
  const { firstname, fullname, lastname, password } = req.body;

  try {
    let query =
      "UPDATE tbl_users SET firstname = ?, fullname = ?, lastname = ?";
    const params = [firstname, fullname, lastname];

    // ✅ ถ้ามีการส่ง password ใหม่มา → hash แล้วเพิ่มเข้า query
    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      query += ", password = ?";
      params.push(hashedPassword);
    }

    query += " WHERE id = ?";
    params.push(id);

    const [result] = await db.query(query, params);
    if (result.affectedRows === 0)
      return res.status(404).json({ message: "User not found" });

    res.json({ message: "User updated successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Update failed" });
  }
});

//POST /Login endpoint เข้าสู่ระบบ
// POST: เข้าสู่ระบบ (Login)
app.post("/login", async (req, res) => {
  const { username, password } = req.body; // ใช้ fullname หรืออาจเปลี่ยนเป็น username ตามโครงสร้างจริง

  try {
    const [rows] = await db.query(
      "SELECT * FROM tbl_users WHERE username = ?",
      [username]
    );
    if (rows.length === 0)
      return res.status(401).json({ error: "User not found" });

    const user = rows[0];

    // ตรวจสอบรหัสผ่าน
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: "Invalid password" });

    // สร้าง JWT token
    const token = jwt.sign(
      { id: user.id, fullname: user.fullname, lastname: user.lastname },
      SECRET_KEY,
      { expiresIn: "1h" } // อายุ token 1 ชั่วโมง
    );

    res.json({ message: "Login successful", token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed" });
  }
});
