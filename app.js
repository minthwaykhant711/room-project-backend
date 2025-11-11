// app.js — CommonJS, port 3000, JWT auth (no sessions), Argon2, static images

const express = require("express");
const mysql = require("mysql2");
const multer = require("multer");
const path = require("path");
const cors = require("cors");
const argon2 = require("argon2");
const jwt = require("jsonwebtoken");
const con = require("./config/config"); 
const app = express();
const JWT_SECRET = "your_super_secret_change_me"; 
const PUBLIC_BASE = "http://localhost:3000";
const PORT = 3000;

// ---------- core middleware ----------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors()); // mobile uses Authorization header; this is fine

// ---------- static image hosting ----------
const uploadsDir = path.join(__dirname, "uploads");
app.use("/uploads", express.static(uploadsDir));

function q(sql, params = []) {
  return new Promise((resolve, reject) => {
    con.query(sql, params, (err, rows) => (err ? reject(err) : resolve(rows)));
  });
}
function signUser(u) {
  // keep small, include safe fields for quick /me
  return jwt.sign(
    {
      id: u.user_id,
      email: u.email,
      role: u.role,
      first_name: u.first_name,
      last_name: u.last_name || "",
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}
function getAuthUser(req) {
  // read Authorization: Bearer <jwt>
  const auth = req.headers.authorization || "";
  const parts = auth.split(" ");
  if (parts.length === 2 && /^Bearer$/i.test(parts[0])) {
    const token = parts[1];
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      return decoded; // {id, email, role, first_name, last_name, iat, exp}
    } catch (e) {
      return null;
    }
  }
  return null;
}
function requireAuth(req, res, next) {
  const user = getAuthUser(req);
  if (!user) return res.status(401).json({ error: "Not logged in" });
  req.user = user;
  next();
}

// ============================================================================
// AUTH
// ============================================================================
// GET /password/:raw   -> dev utility to generate Argon2 hash

app.get("/password/:raw", async (req, res) => {
  const raw = req.params.raw || "";
  if (!raw) return res.status(400).send("Password required");
  try {
    const hash = await argon2.hash(raw, {
      type: argon2.argon2id,
      timeCost: 3,
      memoryCost: 1 << 16,
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

    // sign JWT & return profile like web did before
    const token = signUser(u);
    const userPayload = {
      id: u.user_id,
      email: u.email,
      role: u.role,
      first_name: u.first_name,
      last_name: u.last_name,
      name: `${u.first_name}${u.last_name ? " " + u.last_name : ""}`,
    };
    return res.json({ ok: true, user: userPayload, token });
  });
});
// POST /register/create  { email, password or password_hash, first_name, last_name?, role? }
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

    const u = {
      user_id: result.insertId,
      email,
      first_name,
      last_name,
      role,
    };
    const token = signUser(u);

    const userPayload = {
      id: result.insertId,
      email,
      role,
      first_name,
      last_name,
      name: `${first_name}${last_name ? " " + last_name : ""}`,
    };

    return res.status(201).json({ ok: true, user: userPayload, token });
  } catch (e) {
    console.error("register error:", e);
    return res.status(500).json({ error: "Database error" });
  }
});

// GET /me  -> decode JWT and (optionally) refresh from DB
app.get("/me", requireAuth, async (req, res) => {
  try {
    // If you want to be 100% fresh:
    const rows = await q(
      "SELECT user_id, email, first_name, last_name, role FROM users WHERE user_id = ? LIMIT 1",
      [req.user.id]
    );
    if (!rows.length) return res.status(404).json({ error: "User not found" });

    const u = rows[0];
    const user = {
      id: u.user_id,
      email: u.email,
      role: u.role,
      first_name: u.first_name,
      last_name: u.last_name,
      name: `${u.first_name}${u.last_name ? " " + u.last_name : ""}`,
    };
    return res.json({ ok: true, user });
  } catch (e) {
    console.error("me error:", e);
    return res.status(500).json({ error: "Database error" });
  }
});

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

// OPTIONAL: POST /rooms/:id/image  (admin/staff)
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
// AVAILABILITY for a day
// ============================================================================
//
// GET /rooms/availability?date=YYYY-MM-DD
// returns { ok, date, slots:[{slot_id,start_time,end_time}], rooms:[{id,name,description,image_url,statuses:{'HH:MM - HH:MM': 'available|pending|reserved|passed|disabled'}}] }
app.get("/rooms/availability", async (req, res) => {
  try {
    const ymd = String(req.query.date || "").slice(0, 10);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(ymd)) {
      return res.status(400).json({ error: "date (YYYY-MM-DD) required" });
    }

    const rooms = await q(
      "SELECT room_id, room_name, room_status, description, image FROM room ORDER BY room_name"
    );
    const slots = await q("SELECT slot_id, start_time, end_time FROM time_slot ORDER BY slot_id");

    // bookings for that day that actually block a slot
    const books = await q(
      `
        SELECT b.room_id, b.slot_id, b.booking_status
        FROM booking b
        WHERE b.booking_date = ?
          AND b.booking_status IN ('Waiting','Approved')
      `,
      [ymd]
    );

    // map: roomId -> (slotId -> status)
    const byRoomSlot = new Map();
    for (const b of books) {
      if (!byRoomSlot.has(b.room_id)) byRoomSlot.set(b.room_id, new Map());
      const map = byRoomSlot.get(b.room_id);
      map.set(
        b.slot_id,
        b.booking_status === "Waiting" ? "pending" : "reserved"
      );
    }

    // local server time for "passed" marking
    const now = new Date();
    const nowHHMM = now.toTimeString().slice(0, 5);
    const todayYMD = new Date().toISOString().slice(0, 10);
    const isToday = ymd === todayYMD;

    const slotLabels = slots.map((s) => {
      const st = String(s.start_time).slice(0, 5);
      const et = String(s.end_time).slice(0, 5);
      return { id: s.slot_id, label: `${st} - ${et}`, start: st };
    });

    const outRooms = rooms.map((r) => {
      const statuses = {};
      for (const s of slotLabels) {
        let status = "available";
        if (r.room_status !== 1) {
          // room disabled/offline -> every slot shown as disabled
          status = "disabled";
        } else {
          const slotMap = byRoomSlot.get(r.room_id);
          if (slotMap && slotMap.has(s.id)) {
            status = slotMap.get(s.id); // pending|reserved
          } else if (isToday && nowHHMM >= s.start) {
            // passed slots on the same day: unclickable but NOT disabled
            status = "passed";
          }
        }
        statuses[s.label] = status;
      }
      return {
        id: r.room_id,
        name: r.room_name,
        description: r.description,
        image_url: r.image ? `${PUBLIC_BASE}/uploads/${encodeURIComponent(r.image)}` : null,
        room_status: r.room_status,   
        statuses,
      };
    });

    res.json({
      ok: true,
      date: ymd,
      slots: slots.map((s) => ({
        slot_id: s.slot_id,
        start_time: String(s.start_time).slice(0, 5),
        end_time: String(s.end_time).slice(0, 5),
      })),
      rooms: outRooms,
    });
  } catch (e) {
    console.error("availability error:", e);
    res.status(500).json({ error: "Database error" });
  }
});

// ============================================================================
// BOOKINGS (student/lecturer can create; JWT auth)
// ============================================================================

// POST /bookings  { room_id, slot_id, booking_date:'YYYY-MM-DD', objective }
app.post("/bookings", requireAuth, async (req, res) => {
  try {
    const me = req.user;
    const { room_id, slot_id, booking_date, objective = "" } = req.body || {};
    if (!room_id || !slot_id || !booking_date) {
      return res.status(400).json({ error: "room_id, slot_id, booking_date required" });
    }

    // validate slot
    const slots = await q(
      "SELECT slot_id, start_time FROM time_slot WHERE slot_id = ?",
      [slot_id]
    );
    if (!slots.length) return res.status(400).json({ error: "Invalid slot" });

    // Block booking in the past & passed slot (local server time)
    const ymdToday = new Date().toISOString().slice(0, 10);
    const nowHHMM = new Date().toTimeString().slice(0, 5);
    const slotStart = String(slots[0].start_time).slice(0, 5);
    if (booking_date < ymdToday) {
      return res.status(400).json({ error: "Cannot book in the past" });
    }
    if (booking_date === ymdToday && nowHHMM >= slotStart) {
      return res.status(400).json({ error: "This time slot has already started today" });
    }

    // room exists & available?
    const r = await q("SELECT room_status FROM room WHERE room_id = ?", [room_id]);
    if (!r.length) return res.status(404).json({ error: "Room not found" });
    if (r[0].room_status !== 1) {
      return res.status(409).json({ error: "Room is not available" });
    }

    // prevent double booking (room+date+slot) while Waiting/Approved
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
// returns each booking incl. approver name & reject reason
app.get("/bookings/mine", requireAuth, async (req, res) => {
  try {
    const me = req.user;

    const rows = await q(
      `
      SELECT b.booking_id, b.booking_date, b.booking_status, b.Objective,
             b.reason AS reject_reason, b.approver_id,
             r.room_id, r.room_name,
             t.slot_id, t.start_time, t.end_time,
             u2.first_name AS approver_first, u2.last_name AS approver_last
      FROM booking b
      JOIN room r       ON r.room_id = b.room_id
      JOIN time_slot t  ON t.slot_id = b.slot_id
      LEFT JOIN users u2 ON u2.user_id = b.approver_id
      WHERE b.user_id = ?
      ORDER BY b.booking_date DESC, t.slot_id ASC
    `,
      [me.id]
    );

    const bookings = rows.map((b) => ({
      booking_id: b.booking_id,
      booking_date: b.booking_date,
      booking_status: b.booking_status, // Waiting | Approved | Rejected
      Objective: b.Objective,
      reject_reason: b.reject_reason || "",
      approver_id: b.approver_id,
      approver_name:
        b.approver_first
          ? `${b.approver_first}${b.approver_last ? " " + b.approver_last : ""}`
          : "",
      room_id: b.room_id,
      room_name: b.room_name,
      slot_id: b.slot_id,
      start_time: String(b.start_time).slice(0, 5),
      end_time: String(b.end_time).slice(0, 5),
    }));

    res.json({ ok: true, bookings });
  } catch (e) {
    console.error("bookings mine error:", e);
    res.status(500).json({ error: "Database error" });
  }
});

// ============================================================================
// START SERVER
// ============================================================================
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

module.exports = app;