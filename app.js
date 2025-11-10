// app.js — CommonJS, port 3000, sessions kept for web, header-based auth for mobile
const express = require("express");
const mysql = require("mysql2");
const session = require("express-session");
const multer = require("multer");
const path = require("path");
const cors = require("cors");
const argon2 = require("argon2");
const con = require("./config/config"); // your MySQL connection

const app = express();

// ---------- core middleware ----------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors()); // keep simple; web can still use cookies locally

// ---------- sessions (for the web app) ----------
app.use(
  session({
    secret: "room_project_secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    },
  })
);

// ---------- static image hosting ----------
const PUBLIC_BASE = "http://localhost:3000";
const uploadsDir = path.join(__dirname, "uploads");
app.use("/uploads", express.static(uploadsDir));

// ---------- tiny helper: promisified query ----------
function q(sql, params = []) {
  return new Promise((resolve, reject) => {
    con.query(sql, params, (err, rows) => (err ? reject(err) : resolve(rows)));
  });
}

// ---------- auth helper (session OR header override) ----------
async function attachUserFromAuth(req, _res, next) {
  if (req.session && req.session.user) return next();

  let raw = req.headers["x-user-id"];
  if (!raw && req.headers.authorization) {
    const parts = req.headers.authorization.split(" ");
    if (parts.length === 2 && /^Bearer$/i.test(parts[0])) raw = parts[1];
  }

  if (raw) {
    const id = parseInt(String(raw), 10);
    if (!Number.isNaN(id)) {
      try {
        const rows = await q(
          "SELECT user_id, email, first_name, last_name, role FROM users WHERE user_id = ? LIMIT 1",
          [id]
        );
        if (rows.length) {
          const u = rows[0];
          req.session.user = {
            id: u.user_id,
            email: u.email,
            role: u.role,
            first_name: u.first_name,
            last_name: u.last_name,
            name: `${u.first_name}${u.last_name ? " " + u.last_name : ""}`,
          };
        }
      } catch (e) {
        console.error("attachUserFromAuth error:", e);
      }
    }
  }
  next();
}
app.use(attachUserFromAuth);

// ============================================================================
// AUTH
// ============================================================================

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

    req.session.user = {
      id: u.user_id,
      email: u.email,
      role: u.role,
      first_name: u.first_name,
      last_name: u.last_name,
      name: `${u.first_name}${u.last_name ? " " + u.last_name : ""}`,
    };
    return res.json({
      ok: true,
      user: req.session.user,
      mobile_token: String(u.user_id),
    });
  });
});

// GET /me
app.get("/me", (req, res) => {
  if (!req.session || !req.session.user) {
    return res.status(401).json({ error: "Not logged in" });
  }
  return res.json({ ok: true, user: req.session.user });
});

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

// GET /logout
app.get("/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// ============================================================================
// ROOMS
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
      disabled: r.room_status !== 1, // <-- include disabled flag here too
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
// returns { ok, date, slots:[{slot_id,start_time,end_time}], rooms:[{id,name,description,image_url,disabled,statuses:{'HH:MM - HH:MM': 'available|pending|reserved|passed|disabled'}}] }
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

    // bookings for that day (Waiting/Approved block the slot)
    const books = await q(
      `
        SELECT b.room_id, b.slot_id, b.booking_status
        FROM booking b
        WHERE b.booking_date = ?
          AND b.booking_status IN ('Waiting','Approved')
      `,
      [ymd]
    );

    const byRoomSlot = new Map();
    for (const b of books) {
      if (!byRoomSlot.has(b.room_id)) byRoomSlot.set(b.room_id, new Map());
      const map = byRoomSlot.get(b.room_id);
      map.set(b.slot_id, b.booking_status === "Waiting" ? "pending" : "reserved");
    }

    // compute "passed" for today
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
      const roomDisabled = r.room_status !== 1; // 0 => disabled
      const statuses = {};
      for (const s of slotLabels) {
        let status = "available";
        if (roomDisabled) {
          status = "disabled"; // whole-room disabled → all slots show disabled
        } else {
          const slotMap = byRoomSlot.get(r.room_id);
          if (slotMap && slotMap.has(s.id)) {
            status = slotMap.get(s.id); // pending|reserved
          } else if (isToday && nowHHMM >= s.start) {
            status = "passed";          // already started today
          }
        }
        statuses[s.label] = status;
      }
      return {
        id: r.room_id,
        name: r.room_name,
        description: r.description,
        image_url: r.image ? `${PUBLIC_BASE}/uploads/${encodeURIComponent(r.image)}` : null,
        disabled: roomDisabled, // <-- explicit flag for the frontend to pick overlay message
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
// BOOKINGS
// ============================================================================

app.post("/bookings", async (req, res) => {
  try {
    if (!req.session || !req.session.user) {
      return res.status(401).json({ error: "Not logged in" });
    }
    const me = req.session.user;
    if (me.role !== "student") {
      return res.status(403).json({ error: "Only students book" });
    }

    const { room_id, slot_id, booking_date, objective = "" } = req.body || {};
    if (!room_id || !slot_id || !booking_date) {
      return res.status(400).json({ error: "room_id, slot_id, booking_date required" });
    }

    const slots = await q(
      "SELECT slot_id, start_time FROM time_slot WHERE slot_id = ?",
      [slot_id]
    );
    if (!slots.length) return res.status(400).json({ error: "Invalid slot" });

    const ymdToday = new Date().toISOString().slice(0, 10);
    const nowHHMM = new Date().toTimeString().slice(0, 5);
    const slotStart = String(slots[0].start_time).slice(0, 5);
    if (booking_date < ymdToday) {
      return res.status(400).json({ error: "Cannot book in the past" });
    }
    if (booking_date === ymdToday && nowHHMM >= slotStart) {
      return res.status(400).json({ error: "This time slot has already started today" });
    }

    const r = await q("SELECT room_status FROM room WHERE room_id = ?", [room_id]);
    if (!r.length) return res.status(404).json({ error: "Room not found" });
    if (r[0].room_status !== 1) {
      return res.status(409).json({ error: "Room is not available" });
    }

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

    // NOTE:
    // - LEFT JOIN users u ON u.user_id = b.approver_id  -> name of approver
    // - include b.reason                               -> lecturer's rejection reason
    // - frontend expects `approver_name` and `reject_reason`
    const rows = await q(
      `
      SELECT
        b.booking_id,
        b.booking_date,
        b.booking_status,           -- Waiting | Approved | Rejected
        b.Objective,
        b.reason,                   -- lecturer's reason on Rejected (nullable)
        b.approver_id,              -- who approved/rejected (nullable when Waiting)

        r.room_id,
        r.room_name,

        t.slot_id,
        t.start_time,
        t.end_time,

        u.first_name  AS approver_first,
        u.last_name   AS approver_last
      FROM booking b
      JOIN room r      ON r.room_id = b.room_id
      JOIN time_slot t ON t.slot_id = b.slot_id
      LEFT JOIN users u ON u.user_id = b.approver_id
      WHERE b.user_id = ?
      ORDER BY b.booking_date DESC, t.slot_id ASC
      `,
      [me.id]
    );

    // adapt to what the mobile UI expects
    const bookings = rows.map((b) => {
      const approverName =
        (b.approver_first ? String(b.approver_first) : "") +
        (b.approver_last ? " " + String(b.approver_last) : "");
      return {
        booking_id: b.booking_id,
        booking_date: b.booking_date,
        booking_status: b.booking_status, // Waiting | Approved | Rejected
        Objective: b.Objective,

        // 👇 keys your Flutter page reads:
        approver_name: approverName.trim(),           // "" when Waiting
        reject_reason: b.reason ? String(b.reason) : "",

        room_id: b.room_id,
        room_name: b.room_name,

        slot_id: b.slot_id,
        start_time: String(b.start_time).slice(0, 5),
        end_time: String(b.end_time).slice(0, 5),
      };
    });

    res.json({ ok: true, bookings });
  } catch (e) {
    console.error("bookings mine error:", e);
    res.status(500).json({ error: "Database error" });
  }
});

// ===== Lecturer Dashboard: Room Status Summary =====
app.get('/api/rooms/status-summary', async (req, res) => {
  try {
    // accept optional ?date=YYYY-MM-DD, fallback to server today
    const qDate = String(req.query.date || '').slice(0, 10);
    const ymd = /^\d{4}-\d{2}-\d{2}$/.test(qDate)
      ? qDate
      : new Date().toISOString().slice(0, 10);

    // avoid intermediate caches returning stale counts
    res.set('Cache-Control', 'no-store');

    // load rooms, slots and bookings for the requested date (Waiting/Approved)
    const rooms = await q(
      "SELECT room_id, room_name, room_status, description, image FROM room ORDER BY room_name"
    );
    const slots = await q("SELECT slot_id, start_time, end_time FROM time_slot ORDER BY slot_id");
    const books = await q(
      `
        SELECT b.room_id, b.slot_id, b.booking_status
        FROM booking b
        WHERE b.booking_date = ?
          AND b.booking_status IN ('Waiting','Approved')
      `,
      [ymd]
    );

    // map bookings per room -> slot -> ('pending'|'reserved')
    const byRoomSlot = new Map();
    for (const b of books) {
      if (!byRoomSlot.has(b.room_id)) byRoomSlot.set(b.room_id, new Map());
      byRoomSlot.get(b.room_id).set(b.slot_id, b.booking_status === 'Waiting' ? 'pending' : 'reserved');
    }

    // helpers for slot labels and current time check
    const slotLabels = slots.map((s) => {
      const st = String(s.start_time).slice(0, 5);
      const et = String(s.end_time).slice(0, 5);
      return { id: s.slot_id, label: `${st} - ${et}`, start: st };
    });

    const now = new Date();
    const nowHHMM = now.toTimeString().slice(0, 5);
    const todayYMD = new Date().toISOString().slice(0, 10);
    const isToday = ymd === todayYMD;

    // per-slot (room * slot) entries and counts
    const summary = { available: 0, pending: 0, reserved: 0, disabled: 0, passed: 0 };
    const groups = { available: [], pending: [], reserved: [], disabled: [], passed: [] };
    const entries = []; // each timeslot = one entry

    for (const r of rooms) {
      const roomDisabled = r.room_status !== 1;
      for (const s of slotLabels) {
        let status = 'available';
        if (roomDisabled) {
          status = 'disabled';
        } else {
          const slotMap = byRoomSlot.get(r.room_id);
          if (slotMap && slotMap.has(s.id)) {
            status = slotMap.get(s.id); // pending|reserved
          } else if (isToday && nowHHMM >= s.start) {
            status = 'passed';
          }
        }

        // count and group by status
        if (!Object.prototype.hasOwnProperty.call(summary, status)) {
          summary[status] = 0;
          groups[status] = [];
        }
        summary[status] += 1;

        const item = {
          room_id: r.room_id,
          room_name: r.room_name,
          slot_id: s.id,
          slot_label: s.label,
          status,
          description: r.description,
          image_url: r.image ? `${PUBLIC_BASE}/uploads/${encodeURIComponent(r.image)}` : null,
        };
        groups[status].push(item);
        entries.push(item);
      }
    }

    res.json({
      ok: true,
      date: ymd,
      total_rooms: rooms.length,
      total_slots: rooms.length * slotLabels.length,
      summary,
      groups,
      entries, // frontend can use this for per-timeslot UI
    });
  } catch (err) {
    console.error('status-summary error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});


// ---------------------------------------------------------------------------
// Lecturer endpoints: pending list, lecturer's history, approve & reject
// ---------------------------------------------------------------------------

// GET /bookings/pending?date=YYYY-MM-DD
// Returns bookings with booking_status = 'Waiting' for the given date
app.get('/bookings/pending', async (req, res) => {
  try {
    const ymd = String(req.query.date || '').slice(0, 10);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(ymd)) {
      return res.status(400).json({ error: 'date (YYYY-MM-DD) required' });
    }

    const rows = await q(
      `
      SELECT b.booking_id, b.booking_date, b.booking_status, b.Objective,
             r.room_id, r.room_name,
             t.slot_id, t.start_time, t.end_time,
             u.user_id, u.first_name, u.last_name
      FROM booking b
      JOIN room r ON r.room_id = b.room_id
      JOIN time_slot t ON t.slot_id = b.slot_id
      JOIN users u ON u.user_id = b.user_id
      WHERE b.booking_date = ? AND b.booking_status = 'Waiting'
      ORDER BY t.slot_id ASC
    `,
      [ymd]
    );

    const bookings = rows.map((b) => ({
      booking_id: b.booking_id,
      booking_date: b.booking_date,
      booking_status: b.booking_status,
      objective: b.Objective,
      room_id: b.room_id,
      room_name: b.room_name,
      slot_id: b.slot_id,
      start_time: String(b.start_time).slice(0, 5),
      end_time: String(b.end_time).slice(0, 5),
      user_id: b.user_id,
      booked_by: ((b.first_name || '') + (b.last_name ? ' ' + b.last_name : '')).trim(),
    }));

    res.json({ ok: true, bookings });
  } catch (e) {
    console.error('bookings pending error:', e);
    res.status(500).json({ error: 'Database error' });
  }
});

// GET /bookings/for-lecturer
// Returns bookings that were approved/rejected by the current lecturer (approver_id)
app.get('/bookings/for-lecturer', async (req, res) => {
  try {
    if (!req.session || !req.session.user) return res.status(401).json({ error: 'Not logged in' });
    const me = req.session.user;

    const rows = await q(
      `
      SELECT b.booking_id, b.booking_date, b.booking_status, b.Objective, b.reason, b.approver_id,
             r.room_id, r.room_name,
             t.slot_id, t.start_time, t.end_time,
             u.user_id AS booked_user_id, u.first_name AS booked_first, u.last_name AS booked_last
      FROM booking b
      JOIN room r ON r.room_id = b.room_id
      JOIN time_slot t ON t.slot_id = b.slot_id
      JOIN users u ON u.user_id = b.user_id
      WHERE b.approver_id = ?
      ORDER BY b.booking_date DESC, t.slot_id ASC
    `,
      [me.id]
    );

    const bookings = rows.map((b) => ({
      booking_id: b.booking_id,
      booking_date: b.booking_date,
      booking_status: b.booking_status,
      objective: b.Objective,
      reason: b.reason || '',
      approver_id: b.approver_id,
      room_id: b.room_id,
      room_name: b.room_name,
      slot_id: b.slot_id,
      start_time: String(b.start_time).slice(0, 5),
      end_time: String(b.end_time).slice(0, 5),
      booked_by: ((b.booked_first || '') + (b.booked_last ? ' ' + b.booked_last : '')).trim(),
    }));

    res.json({ ok: true, bookings });
  } catch (e) {
    console.error('bookings for-lecturer error:', e);
    res.status(500).json({ error: 'Database error' });
  }
});

// POST /bookings/:id/approve
app.post('/bookings/:id/approve', async (req, res) => {
  try {
    if (!req.session || !req.session.user) return res.status(401).json({ error: 'Not logged in' });
    const me = req.session.user;

    const id = parseInt(String(req.params.id), 10);
    if (Number.isNaN(id)) return res.status(400).json({ error: 'Invalid booking id' });

    const rows = await q('SELECT booking_id FROM booking WHERE booking_id = ? LIMIT 1', [id]);
    if (!rows.length) return res.status(404).json({ error: 'Booking not found' });

    await q('UPDATE booking SET booking_status = ?, approver_id = ?, reason = NULL WHERE booking_id = ?', [
      'Approved', me.id, id,
    ]);

    res.json({ ok: true });
  } catch (e) {
    console.error('approve booking error:', e);
    res.status(500).json({ error: 'Database error' });
  }
});

// POST /bookings/:id/reject  { reason }
app.post('/bookings/:id/reject', async (req, res) => {
  try {
    if (!req.session || !req.session.user) return res.status(401).json({ error: 'Not logged in' });
    const me = req.session.user;
    const id = parseInt(String(req.params.id), 10);
    if (Number.isNaN(id)) return res.status(400).json({ error: 'Invalid booking id' });
    const reason = String(req.body.reason || '').trim();

    const rows = await q('SELECT booking_id FROM booking WHERE booking_id = ? LIMIT 1', [id]);
    if (!rows.length) return res.status(404).json({ error: 'Booking not found' });

    await q('UPDATE booking SET booking_status = ?, approver_id = ?, reason = ? WHERE booking_id = ?', [
      'Rejected', me.id, reason, id,
    ]);

    res.json({ ok: true });
  } catch (e) {
    console.error('reject booking error:', e);
    res.status(500).json({ error: 'Database error' });
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
