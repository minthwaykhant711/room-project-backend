const express = require("express");
const mysql = require("mysql2");
const argon2 = require('@node-rs/argon2');
const con = require('./db');
// add this helper so routes can use `await q(sql, params)`
const q = (sql, params = []) =>
  new Promise((resolve, reject) => {
    con.query(sql, params, (err, results) => (err ? reject(err) : resolve(results)));
  });
const session = require("express-session");
const multer = require("multer");
const path = require("path");
const cors = require("cors");


const app = express();
app.use(express.json());
app.use(cors()); // allow Flutter to access backend

app.use('/images', express.static('images'));

app.use(session({
  secret: "mobile-room-reserve-secret",
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false },
}));

//password generate //correct
app.get('/api/password/:raw', (req, res) => {
   const raw = req.params.raw;
   const hash = argon2.hashSync(raw);
    // console.log(hash.length);
    // 97 characters
   res.send(hash);
});


app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: "Email and password required" });
    }

    const sql = "SELECT * FROM users WHERE email = ?";
    con.query(sql, [email], async (err, result) => {
      if (err) return res.status(500).json({ message: "Database error" });
      if (result.length === 0)
        return res.status(401).json({ message: "User not found" });

      const user = result[0];

      // Use argon2 to verify password
      const isPasswordValid = await argon2.verify(user.password, password);
      if (!isPasswordValid)
        return res.status(401).json({ message: "Incorrect password" });

      // Save user session
      req.session.user = user;

      return res.status(200).json({
        message: "Login successful",
        user_id: user.user_id,
        role: user.role,
        first_name: user.first_name,
        last_name: user.last_name,
      });
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Server error" });
  }
});

//register
// POST /register/create
app.post("/register/create", async (req, res) => {
  const {
    email,
    password,
    password_hash,
    first_name,
    last_name = "",
    role = "student",
  } = req.body || {};

  if (!email || !first_name || (!password && !password_hash)) {
    return res
      .status(400)
      .json({ error: "email, first_name and password or password_hash required" });
  }

  try {
    const dup = await q("SELECT user_id FROM users WHERE email = ? LIMIT 1", [email]);
    if (dup.length) return res.status(409).json({ error: "Email already registered" });

    let toStore = password_hash;
    if (!toStore) {
      toStore = await argon2.hash(password, {
        type: argon2.argon2id,
        timeCost: 3,
        memoryCost: 1 << 16,
        parallelism: 1,
        hashLength: 32,
        saltLength: 16,
      });
    }

    const result = await q(
      "INSERT INTO users(email, password, first_name, last_name, role) VALUES (?,?,?,?,?)",
      [email, toStore, first_name, last_name, role]
    );

    req.session.user = {
      id: result.insertId,
      email,
      role,
      first_name,
      last_name,
      name: `${first_name}${last_name ? " " + last_name : ""}`,
    };

    return res.status(201).json({
      ok: true,
      user: req.session.user,
      mobile_token: String(result.insertId),
    });
  } catch (e) {
    console.error("register error:", e);
    return res.status(500).json({ error: "Database error" });
  }
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
    SELECT 
      b.booking_id,
      b.booking_date,
      b.booking_status,
      b.reason,
      r.room_name,
      t.start_time,
      t.end_time,
      CONCAT(a.first_name, ' ', a.last_name) AS approver_name
    FROM booking b
    JOIN room r ON b.room_id = r.room_id
    JOIN time_slot t ON b.slot_id = t.slot_id
    LEFT JOIN users a ON b.approver_id = a.user_id
    WHERE b.user_id = ?
    ORDER BY b.booking_date DESC, t.start_time ASC
  `;

  con.query(sql, [user_id], (err, results) => {
    if (err) {
      console.error("❌ Error fetching student bookings:", err);
      return res.status(500).json({ message: "Server error" });
    }

    res.json(results);
  });
});



// ===============================
// GET ALL TIME SLOTS
// ===============================
app.get("/api/timeslots", (req, res) => {
  const sql = "SELECT * FROM time_slot ORDER BY start_time";
  con.query(sql, (err, result) => {
    if (err) return res.status(500).json({ message: "Error fetching time slots" });
    res.status(200).json(result);
  });
});

// ===============================
// GET BOOKINGS WITH ROOM INFO BY DATE
// ===============================
app.get("/api/bookings_by_date", (req, res) => {
  const { date } = req.query;
  if (!date) return res.status(400).json({ message: "Date is required" });

  const sql = `
    SELECT b.room_id, b.slot_id, b.booking_status, b.user_id, t.start_time
    FROM booking b
    JOIN time_slot t ON b.slot_id = t.slot_id
    WHERE b.booking_date = ? AND b.booking_status IN ('Pending','Approved')
  `;

  con.query(sql, [date], (err, rows) => {
    if (err) {
      console.error("Error fetching bookings_by_date:", err);
      return res.status(500).json({ message: "Error fetching bookings" });
    }

    const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
    const now = new Date();

    const result = rows.map(r => {
      let disabled = false;
      if (date === today && r.start_time) {
        const slotDateTime = new Date(`${date}T${r.start_time}`);
        if (slotDateTime <= now) disabled = true;
      }
      return {
        room_id: r.room_id,
        slot_id: r.slot_id,
        booking_status: r.booking_status,
        user_id: r.user_id,
        start_time: r.start_time,
        disabled,
      };
    });

    res.status(200).json(result);
  });
});






// // ===============================
// // LOGOUT
// // ===============================
// app.post("/logout", (req, res) => {
//   req.session.destroy(() => {
//     res.status(200).json({ message: "Logged out successfully" });
//   });
// });




// // ===============================
// // CREATE BOOKING
// // ===============================
app.post("/api/book", (req, res) => {
  const { user_id, room_id, slot_id, booking_date, Objective } = req.body;

  if (!user_id || !room_id || !slot_id || !booking_date)
    return res.status(400).json({ message: "Missing required fields" });

  // enforce booking only for today
  const today = new Date().toISOString().slice(0, 10);
  if (booking_date !== today) {
    return res.status(400).json({ message: "Bookings are allowed for today only" });
  }

  // 1) get slot start_time
  const slotSql = "SELECT start_time FROM time_slot WHERE slot_id = ?";
  con.query(slotSql, [slot_id], (err, slotRows) => {
    if (err) return res.status(500).json({ message: "Server error (slot lookup)" });
    if (!slotRows || slotRows.length === 0) return res.status(400).json({ message: "Invalid slot" });

    const startTime = (slotRows[0].start_time || '').toString();
    const slotDateTime = new Date(`${booking_date}T${startTime}`);
    const now = new Date();
    if (slotDateTime <= now) {
      return res.status(400).json({ message: "This time slot is no longer available (already started)" });
    }

    // <-- NEW: check room status (disabled rooms cannot be booked)
    const roomStatusSql = "SELECT room_status FROM room WHERE room_id = ?";
    con.query(roomStatusSql, [room_id], (errRoom, roomRows) => {
      if (errRoom) return res.status(500).json({ message: "Server error (room lookup)" });
      if (!roomRows || roomRows.length === 0) return res.status(400).json({ message: "Invalid room" });
      if (roomRows[0].room_status !== 1) {
        return res.status(400).json({ message: "Room is disabled and cannot be booked" });
      }

      // 2) check if room slot already booked (Pending/Approved)
      const roomSlotSql = `
        SELECT booking_id FROM booking
        WHERE room_id = ? AND slot_id = ? AND booking_date = ?
        AND booking_status IN ('Pending','Approved')
        LIMIT 1
      `;
      con.query(roomSlotSql, [room_id, slot_id, booking_date], (err2, rs) => {
        if (err2) return res.status(500).json({ message: "Server error (room-slot lookup)" });
        if (rs && rs.length > 0) {
          return res.status(409).json({ message: "This room's time slot is already booked" });
        }

        // 3) check if user already has a booking today (Pending/Approved)
        const userSql = `
          SELECT booking_id FROM booking
          WHERE user_id = ? AND booking_date = ?
          AND booking_status IN ('Pending','Approved')
          LIMIT 1
        `;
        con.query(userSql, [user_id, booking_date], (err3, ur) => {
          if (err3) return res.status(500).json({ message: "Server error (user booking lookup)" });
          if (ur && ur.length > 0) {
            return res.status(409).json({ message: "User already has a booking for today" });
          }

          // 4) Insert booking as Pending
          const insertSql = `
            INSERT INTO booking (user_id, room_id, slot_id, booking_date, Objective, booking_status)
            VALUES (?, ?, ?, ?, ?, 'Pending')
          `;
          con.query(insertSql, [user_id, room_id, slot_id, booking_date, Objective || null], (err4, result) => {
            if (err4) return res.status(500).json({ message: "Error creating booking" });
            return res.status(200).json({ message: "Booking request submitted" });
          });
        });
      });
    });
  });
});






// ===============================
// SERVER START
// ===============================
const PORT = 3000;
app.listen(PORT, () => console.log(`📱 Mobile API running on port ${PORT}`));
