const express = require("express");
const mysql = require("mysql2");
const session = require("express-session");
const multer = require("multer");
const path = require("path");
const cors = require("cors");
const argon2 = require("argon2");
const con = require("./config/config");

const app = express();

// ---------- core middleware ----------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors()); // if you later need cookies from mobile, switch to: cors({ origin: true, credentials: true })

// ---------- sessions ----------
app.use(
  session({
    secret: "room_project_secret", // keep it hardcoded per your preference
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    },
  })
);

// ---------- static image hosting ----------
const PUBLIC_BASE = "http://localhost:3000";
const uploadsDir = path.join(__dirname, "uploads");
app.use("/uploads", express.static(uploadsDir)); // -> http://localhost:3000/uploads/<filename>

// ---------- tiny helper: promisified query ----------
function q(sql, params = []) {
  return new Promise((resolve, reject) => {
    con.query(sql, params, (err, rows) => (err ? reject(err) : resolve(rows)));
  });
}

// ============================================================================
// AUTH
// ============================================================================

// GET /password/:raw   -> utility to generate Argon2 hash (teacher-style)
app.get("/password/:raw", async (req, res) => {
  const raw = req.params.raw || "";
  if (!raw) return res.status(400).send("Password required");
  try {
    const hash = await argon2.hash(raw, {
      type: argon2.argon2id,
      timeCost: 3,
      memoryCost: 1 << 16, // 64 MB
      parallelism: 1,
      hashLength: 32,
      saltLength: 16,
    });
    res.send(hash);
  } catch (e) {
    console.error("argon2 hash error:", e);
    res.status(500).send("Hashing failed");
  }
});

// POST /login   { email, password }
app.post("/login", (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: "email and password required" });
  }

  const sql = `
    SELECT user_id, email, password, first_name, last_name, role
    FROM users
    WHERE email = ?
    LIMIT 1
  `;
  con.query(sql, [email], async (err, rows) => {
    if (err) {
      console.error("DB select error:", err);
      return res.status(500).json({ error: "Database error" });
    }
    if (!rows.length) return res.status(401).json({ error: "Wrong email" });

    const u = rows[0];
    try {
      const ok = await argon2.verify(u.password || "", password);
      if (!ok) return res.status(401).json({ error: "Wrong password" });
    } catch (e) {
      console.error("Argon2 verify error:", e);
      return res.status(500).json({ error: "Verification failed" });
    }

    // store full profile in session for inner pages
    req.session.user = {
      id: u.user_id,
      email: u.email,
      role: u.role,
      first_name: u.first_name,
      last_name: u.last_name,
      name: `${u.first_name}${u.last_name ? " " + u.last_name : ""}`,
    };

    return res.json({ ok: true, user: req.session.user });
  });
});

// GET /me  -> returns session user if logged in
app.get("/me", (req, res) => {
  if (!req.session || !req.session.user) {
    return res.status(401).json({ error: "Not logged in" });
  }
  return res.json({ ok: true, user: req.session.user });
});

// POST /register/create
// Option A: send { email, password, first_name, last_name?, role? }  -> server hashes
// Option B: send { email, password_hash, first_name, last_name?, role? } -> stored as-is
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

    return res.status(201).json({ ok: true, user: req.session.user });
  } catch (e) {
    console.error("register error:", e);
    return res.status(500).json({ error: "Database error" });
  }
});

// GET /logout
app.get("/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// ============================================================================
// ROOMS  (no location column; image served via /uploads; DB stores filename only)
// ============================================================================

// GET /rooms?available=1
app.get("/rooms", async (req, res) => {
  try {
    const onlyAvailable = String(req.query.available || "") === "1";
    const rows = await q(
      `
      SELECT room_id, room_name, room_status, description, image
      FROM room
      ${onlyAvailable ? "WHERE room_status = 1" : ""}
      ORDER BY room_name
    `
    );
    const rooms = rows.map((r) => ({
      id: r.room_id,
      name: r.room_name,
      status: r.room_status === 1 ? "available" : "unavailable",
      description: r.description,
      image_url: r.image ? `${PUBLIC_BASE}/uploads/${encodeURIComponent(r.image)}` : null,
    }));
    res.json({ ok: true, rooms });
  } catch (e) {
    console.error("rooms error:", e);
    res.status(500).json({ error: "Database error" });
  }
});

// OPTIONAL: POST /rooms/:id/image  (admin/staff) — uploads a new image file, saves filename in DB
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadsDir),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname || "");
    const base = Date.now().toString(36) + Math.random().toString(16).slice(2);
    cb(null, base + ext.toLowerCase());
  },
});
const upload = multer({ storage });

app.post("/rooms/:id/image", upload.single("image"), async (req, res) => {
  try {
    const id = req.params.id;
    if (!req.file) return res.status(400).send("No file uploaded");
    await q("UPDATE room SET image = ? WHERE room_id = ?", [req.file.filename, id]);
    res.json({
      ok: true,
      filename: req.file.filename,
      url: `${PUBLIC_BASE}/uploads/${req.file.filename}`,
    });
  } catch (e) {
    console.error("upload error:", e);
    res.status(500).send("Upload failed");
  }
});

// ============================================================================
// TIME SLOTS
// ============================================================================

// GET /time-slots
app.get("/time-slots", async (_req, res) => {
  try {
    const rows = await q(
      "SELECT slot_id, start_time, end_time FROM time_slot ORDER BY slot_id ASC"
    );
    res.json({ ok: true, slots: rows });
  } catch (e) {
    console.error("time-slots error:", e);
    res.status(500).json({ error: "Database error" });
  }
});

// ============================================================================
// BOOKINGS (student/lecturer can create; relies on session user)
// ============================================================================

// POST /bookings  { room_id, slot_id, booking_date:'YYYY-MM-DD', objective }
app.post("/bookings", async (req, res) => {
  try {
    if (!req.session || !req.session.user) {
      return res.status(401).json({ error: "Not logged in" });
    }
    const me = req.session.user;
    if (me.role !== "student" && me.role !== "lecturer") {
      return res.status(403).json({ error: "Only students/lecturers can book" });
    }

    const { room_id, slot_id, booking_date, objective = "" } = req.body || {};
    if (!room_id || !slot_id || !booking_date) {
      return res.status(400).json({ error: "room_id, slot_id, booking_date required" });
    }

    // Bangkok local date (UTC+7)
    const tzOffsetMin = 7 * 60;
    const nowLocal = new Date(new Date().getTime() + tzOffsetMin * 60000);
    const ymdToday = nowLocal.toISOString().slice(0, 10);
    if (booking_date < ymdToday) {
      return res.status(400).json({ error: "Cannot book in the past" });
    }

    // validate slot
    const slots = await q(
      "SELECT slot_id, start_time, end_time FROM time_slot WHERE slot_id = ?",
      [slot_id]
    );
    if (!slots.length) return res.status(400).json({ error: "Invalid slot" });

    // if booking today, ensure slot not started
    if (booking_date === ymdToday) {
      const nowHHMM = nowLocal.toISOString().slice(11, 16); // approx local HH:MM
      const slotStart = String(slots[0].start_time).slice(0, 5);
      if (nowHHMM >= slotStart) {
        return res.status(400).json({ error: "This time slot has already started today" });
      }
    }

    // room exists & available?
    const r = await q("SELECT room_status FROM room WHERE room_id = ?", [room_id]);
    if (!r.length) return res.status(404).json({ error: "Room not found" });
    if (r[0].room_status !== 1) {
      return res.status(409).json({ error: "Room is not available" });
    }

    // prevent double booking (room+date+slot) in Waiting/Approved
    const conflict = await q(
      `
      SELECT booking_id FROM booking
      WHERE room_id = ? AND slot_id = ? AND booking_date = ?
        AND booking_status IN ('Waiting','Approved')
      LIMIT 1
    `,
      [room_id, slot_id, booking_date]
    );
    if (conflict.length) {
      return res.status(409).json({ error: "Time slot already booked for this room" });
    }

    // one active booking per day per user
    const myDay = await q(
      `
      SELECT booking_id FROM booking
      WHERE user_id = ? AND booking_date = ?
        AND booking_status IN ('Waiting','Approved')
      LIMIT 1
    `,
      [me.id, booking_date]
    );
    if (myDay.length) {
      return res.status(409).json({ error: "You already have an active booking for this day" });
    }

    // insert as Waiting
    const ins = await q(
      `
      INSERT INTO booking(user_id, room_id, slot_id, booking_date, Objective, booking_status, created_time)
      VALUES (?,?,?,?,?,'Waiting', NOW())
    `,
      [me.id, room_id, slot_id, booking_date, objective]
    );

    res.status(201).json({ ok: true, id: ins.insertId });
  } catch (e) {
    console.error("bookings create error:", e);
    res.status(500).json({ error: "Database error" });
  }
});

// GET /bookings/mine
app.get("/bookings/mine", async (req, res) => {
  try {
    if (!req.session || !req.session.user) {
      return res.status(401).json({ error: "Not logged in" });
    }
    const me = req.session.user;

    const rows = await q(
      `
      SELECT b.booking_id, b.booking_date, b.booking_status, b.Objective,
             r.room_id, r.room_name,
             t.slot_id, t.start_time, t.end_time
      FROM booking b
      JOIN room r     ON r.room_id = b.room_id
      JOIN time_slot t ON t.slot_id = b.slot_id
      WHERE b.user_id = ?
      ORDER BY b.booking_date DESC, t.slot_id ASC
    `,
      [me.id]
    );

    res.json({ ok: true, bookings: rows });
  } catch (e) {
    console.error("bookings mine error:", e);
    res.status(500).json({ error: "Database error" });
  }
});

// ============================================================================
// START SERVER
// ============================================================================
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

module.exports = app;
