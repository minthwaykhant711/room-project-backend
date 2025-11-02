const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const session = require("express-session");
const multer = require("multer");
const path = require("path");
const cors = require("cors");

// Import DB connection
const con = require("./config/config"); // make sure you have db.js or config/config.js

const app = express();
app.use(express.json());
app.use(cors()); // allow Flutter to access backend

app.use(session({
  secret: "mobile-room-reserve-secret",
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false },
}));

// Serve uploaded images if needed
app.use("/images", express.static(path.join(__dirname, "images")));
const upload = multer({ dest: "images/" });

// ===============================
// LOGIN
// ===============================
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ message: "Email and password required" });

  const sql = "SELECT * FROM users WHERE email = ?";
  con.query(sql, [email], async (err, result) => {
    if (err) return res.status(500).json({ message: "Database error" });
    if (result.length === 0)
      return res.status(401).json({ message: "User not found" });

    const user = result[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid)
      return res.status(401).json({ message: "Incorrect password" });

    req.session.user = user;
    return res.status(200).json({
      message: "Login successful",
      user_id: user.user_id,
      role: user.role,
      first_name: user.first_name,
      last_name: user.last_name,
    });
  });
});

// ===============================
// LOGOUT
// ===============================
app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.status(200).json({ message: "Logged out successfully" });
  });
});

// ===============================
// GET ALL ROOMS
// ===============================
app.get("/api/rooms", (req, res) => {
  const sql = "SELECT * FROM room";
  con.query(sql, (err, result) => {
    if (err) return res.status(500).json({ message: "Error fetching rooms" });
    res.status(200).json(result);
  });
});

// ===============================
// GET BOOKINGS BY USER
// ===============================
app.get("/api/bookings/:user_id", (req, res) => {
  const { user_id } = req.params;
  const sql = `
    SELECT b.*, r.room_name, t.start_time, t.end_time
    FROM booking b
    JOIN room r ON b.room_id = r.room_id
    JOIN time_slot t ON b.slot_id = t.slot_id
    WHERE b.user_id = ?
    ORDER BY b.created_time DESC
  `;
  con.query(sql, [user_id], (err, result) => {
    if (err) return res.status(500).json({ message: "Error fetching bookings" });
    res.status(200).json(result);
  });
});

// ===============================
// CREATE BOOKING
// ===============================
app.post("/api/book", (req, res) => {
  const { user_id, room_id, slot_id, booking_date, Objective } = req.body;

  if (!user_id || !room_id || !slot_id || !booking_date)
    return res.status(400).json({ message: "Missing required fields" });

  const sql = `
    INSERT INTO booking (user_id, room_id, slot_id, booking_date, Objective, booking_status)
    VALUES (?, ?, ?, ?, ?, 'Waiting')
  `;
  con.query(sql, [user_id, room_id, slot_id, booking_date, Objective || null], (err, result) => {
    if (err) return res.status(500).json({ message: "Error creating booking" });
    res.status(200).json({ message: "Booking request submitted" });
  });
});

// ===============================
// APPROVE / REJECT BOOKING (for staff or lecturer)
// ===============================
app.post("/api/booking/decision", (req, res) => {
  const { booking_id, approver_id, status } = req.body;

  if (!booking_id || !approver_id || !status)
    return res.status(400).json({ message: "Missing required fields" });

  const sql = `
    UPDATE booking
    SET booking_status = ?, approver_id = ?
    WHERE booking_id = ?
  `;
  con.query(sql, [status, approver_id, booking_id], (err, result) => {
    if (err) return res.status(500).json({ message: "Error updating booking" });
    res.status(200).json({ message: `Booking ${status}` });
  });
});

// ===============================
// SERVER START
// ===============================
const PORT = 3000;
app.listen(PORT, () => console.log(`📱 Mobile API running on port ${PORT}`));
