const express = require("express");
const app = express();
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2/promise");
require("dotenv").config();

app.use(cors());
app.use(express.json());

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

function authMiddleware(req, res, next) {
  try {
    const authHeader = req.headers["authorization"];

    if (!authHeader) {
      return res.status(401).json({ message: "ไม่มี token ใน header" });
    }

    const parts = authHeader.split(" ");

    if (parts.length !== 2 || parts[0] !== "Bearer") {
      return res.status(401).json({ message: "รูปแบบ Token ไม่ถูกต้อง" });
    }

    const token = parts[1];

    // verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    req.user = decoded;

    next();
  } catch (err) {
    return res.status(401).json({ message: "Token ไม่ถูกต้องหรือหมดอายุ" });
  }
}

app.post("/auth/register", async (req, res) => {
  try {
    const { username, password, fullname, address, phone, email } = req.body;

    if (!username || !password || !fullname)
      return res.status(400).json({ message: "กรอกข้อมูลไม่ครบ" });

    const [exists] = await pool.query(
      "SELECT id FROM tbl_customers WHERE username = ?",
      [username]
    );

    if (exists.length > 0) {
      return res.status(400).json({ message: "username ถูกใช้งานแล้ว" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      `INSERT INTO tbl_customers 
      (username, password, fullname, address, phone, email) 
      VALUES (?, ?, ?, ?, ?, ?)`,
      [username, hashedPassword, fullname, address, phone, email]
    );

    res.json({ message: "สมัครสมาชิกสำเร็จ" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "เซิร์ฟเวอร์ผิดพลาด" });
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: "กรอกข้อมูลไม่ครบ" });
    }

    const [rows] = await pool.query(
      "SELECT * FROM tbl_customers WHERE username = ?",
      [username]
    );

    if (rows.length === 0) {
      return res.status(400).json({ message: "ไม่พบผู้ใช้งาน" });
    }

    const user = rows[0];

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "รหัสผ่านไม่ถูกต้อง" });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    return res.json({ token });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "เซิร์ฟเวอร์ผิดพลาด" });
  }
});

app.get("/customers", authMiddleware, async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT id, username, fullname, address, phone, email, created_at FROM tbl_customers"
    );

    res.json({ data: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "เซิร์ฟเวอร์ผิดพลาด" });
  }
});

app.get("/menus", async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT 
        m.menu_id,
        m.name AS menu_name,
        m.description AS menu_description,
        m.price,
        m.category,
        r.restaurant_id,
        r.name AS restaurant_name,
        r.address AS restaurant_address,
        r.phone AS restaurant_phone,
        r.menu_description AS restaurant_menu_description
      FROM tbl_menus m
      JOIN tbl_restaurants r
        ON m.restaurant_id = r.restaurant_id
    `);

    res.json({ data: rows });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "เซิร์ฟเวอร์ผิดพลาด" });
  }
});

app.post("/orders", authMiddleware, async (req, res) => {
  try {
    const { menu_id, quantity } = req.body;

    if (!menu_id || !quantity) {
      return res.status(400).json({ message: "ส่งข้อมูลไม่ครบ" });
    }

    const [menuRows] = await pool.query(
      "SELECT price, restaurant_id FROM tbl_menus WHERE menu_id = ?",
      [menu_id]
    );

    if (menuRows.length === 0) {
      return res.status(400).json({ message: "ไม่พบเมนูนี้" });
    }

    const price = menuRows[0].price;
    const restaurant_id = menuRows[0].restaurant_id;

    const total = price * quantity;

    const customer_id = req.user.id;

    await pool.query(
      `
      INSERT INTO tbl_orders 
      (restaurant_id, menu_id, quantity, price, total, status, customer_id)
      VALUES (?, ?, ?, ?, ?, 'Processing', ?)
      `,
      [restaurant_id, menu_id, quantity, price, total, customer_id]
    );

    return res.json({
      message: "สร้างคำสั่งซื้อสำเร็จ",
      order: {
        restaurant_id,
        menu_id,
        quantity,
        price,
        total,
        customer_id,
      },
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "เซิร์ฟเวอร์ผิดพลาด" });
  }
});

app.get("/orders/summary", authMiddleware, async (req, res) => {
  try {
    const customer_id = req.user.id;

    const [rows] = await pool.query(
      `
      SELECT 
        c.fullname AS customer_name,
        SUM(o.total) AS total_amount
      FROM tbl_orders o
      JOIN tbl_customers c ON o.customer_id = c.id
      JOIN tbl_menus m ON o.menu_id = m.menu_id
      WHERE o.customer_id = ?
      `,
      [customer_id]
    );

    if (!rows || rows.length === 0) {
      return res.json({ customer_name: null, total_amount: 0 });
    }

    return res.json({
      customer_name: rows[0].customer_name,
      total_amount: rows[0].total_amount || 0,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "เซิร์ฟเวอร์ผิดพลาด" });
  }
});

const PORT = process.env.PORT;

app.listen(PORT, () => console.log(`Server running on port : ${PORT}`));

app.get("/", (req, res) => res.send(`Server running on port : ${PORT}`));

app.get("/ping", async (req, res) => {
  const time = await pool.query("SELECT now() AS now");
  return res.json({
    message: "ok",
    time: time[0],
  });
});
