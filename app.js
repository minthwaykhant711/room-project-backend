// app.js — CommonJS, port 3000, JWT auth (no sessions), Argon2, static images

const express = require("express");
const mysql = require("mysql2");
const multer = require("multer");
const path = require("path");
const cors = require("cors");
const argon2 = require("argon2");
const jwt = require("jsonwebtoken");
const con = require("./config/config");
const fs = require('fs');
const app = express();
const JWT_SECRET = "your_super_secret_change_me";
const PUBLIC_BASE = "http://localhost:3000";
const PORT = 3000;


app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());


const uploadsDir = path.join(__dirname, "uploads");
app.use("/uploads", express.static(uploadsDir));
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadsDir),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname || "");
    const base = Date.now().toString(36) + Math.random().toString(16).slice(2);
    cb(null, base + ext.toLowerCase());
  },
});
const upload = multer({ storage });

function q(sql, params = []) {
  return new Promise((resolve, reject) => {
    con.query(sql, params, (err, rows) => (err ? reject(err) : resolve(rows)));
  });
}
function signUser(u) {
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
  const auth = req.headers.authorization || "";
  const parts = auth.split(" ");
  if (parts.length === 2 && /^Bearer$/i.test(parts[0])) {
    const token = parts[1];
    try {
      return jwt.verify(token, JWT_SECRET);
    } catch {
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
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: "Not logged in" });
    if (!roles.includes(req.user.role))
      return res.status(403).json({ error: "Forbidden" });
    next();
  };
}

// POST /api/login   { email, password }
app.post("/api/login", (req, res) => {
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

// POST /api/register/create
app.post("/api/register/create", async (req, res) => {
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
    const dup = await q("SELECT user_id FROM users WHERE email = ? LIMIT 1", [
      email,
    ]);
    if (dup.length)
      return res.status(409).json({ error: "Email already registered" });

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

// GET /common/user_auth
app.get("/common/user_auth", requireAuth, async (req, res) => {
  try {
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
// ROOMS AVAILABILITY (now includes capacity)
// ============================================================================
app.get("/common/rooms/availability", async (req, res) => {
  try {
    const ymd = String(req.query.date || "").slice(0, 10);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(ymd)) {
      return res.status(400).json({ error: "date (YYYY-MM-DD) required" });
    }

    const rooms = await q(
      "SELECT room_id, room_name, room_status, description, image, capacity FROM room ORDER BY room_name"
    );
    const slots = await q(
      "SELECT slot_id, start_time, end_time FROM time_slot ORDER BY slot_id"
    );

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
      map.set(
        b.slot_id,
        b.booking_status === "Waiting" ? "pending" : "reserved"
      );
    }

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
          status = "disabled";
        } else {
          const slotMap = byRoomSlot.get(r.room_id);
          if (slotMap && slotMap.has(s.id)) {
            status = slotMap.get(s.id); // pending|reserved
          } else if (isToday && nowHHMM >= s.start) {
            status = "passed";
          }
        }
        statuses[s.label] = status;
      }
      return {
        id: r.room_id,
        name: r.room_name,
        description: r.description,
        image_url: r.image
          ? `${PUBLIC_BASE}/uploads/${encodeURIComponent(r.image)}`
          : null,
        room_status: r.room_status,
        capacity: Number(r.capacity ?? 0), 
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
// Student BOOKINGS
// ============================================================================
app.post("/student/bookings", requireAuth, async (req, res) => {
  try {
    const me = req.user;
    const { room_id, slot_id, booking_date, objective = "" } = req.body || {};
    if (!room_id || !slot_id || !booking_date) {
      return res
        .status(400)
        .json({ error: "room_id, slot_id, booking_date required" });
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
      return res
        .status(400)
        .json({ error: "This time slot has already started today" });
    }

    const r = await q("SELECT room_status FROM room WHERE room_id = ?", [
      room_id,
    ]);
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
      return res
        .status(409)
        .json({ error: "Time slot already booked for this room" });
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
      return res
        .status(409)
        .json({ error: "You already have an active booking for this day" });
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

// GET Booking of(student)
app.get("/student/bookings/history", requireAuth, async (req, res) => {
  try {
    const me = req.user;

    const rows = await q(
      `
      SELECT
        b.booking_id,
        DATE_FORMAT(b.booking_date, '%Y-%m-%d') AS booking_date_ymd,
        b.booking_status,
        b.Objective,
        b.reason AS reject_reason,
        b.approver_id,
        r.room_id,
        r.room_name,
        t.slot_id,
        t.start_time,
        t.end_time,
        u2.first_name AS approver_first,
        u2.last_name  AS approver_last
      FROM booking b
      JOIN room r       ON r.room_id = b.room_id
      JOIN time_slot t  ON t.slot_id = b.slot_id
      LEFT JOIN users u2 ON u2.user_id = b.approver_id
      WHERE b.user_id = ?
      ORDER BY b.booking_id DESC
    `,
      [me.id]
    );

    const bookings = rows.map((b) => ({
      booking_id: b.booking_id,
      booking_date: b.booking_date_ymd,        // 👈 fixed
      booking_status: b.booking_status,        // Waiting | Approved | Rejected
      Objective: b.Objective,
      reject_reason: b.reject_reason || "",
      approver_id: b.approver_id,
      approver_name: b.approver_first
        ? `${b.approver_first}${
            b.approver_last ? " " + b.approver_last : ""
          }`
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
// LECTURER: pending/history/approve/reject
// ============================================================================
const ensureLecturer = [requireAuth, requireRole("lecturer")];

app.get("/lecturer/bookings/pending", ensureLecturer, async (_req, res) => {
  try {
    const rows = await q(
      `
      SELECT
        b.booking_id,
        DATE_FORMAT(b.booking_date, '%Y-%m-%d') AS booking_date_ymd,
        b.booking_status,
        b.user_id,
        b.slot_id,
        r.room_name,
        t.start_time,
        t.end_time,
        u.first_name AS student_first,
        u.last_name  AS student_last
      FROM booking b
      JOIN room r      ON r.room_id = b.room_id
      JOIN time_slot t ON t.slot_id = b.slot_id
      JOIN users u     ON u.user_id = b.user_id
      WHERE b.booking_status = 'Waiting'
      ORDER BY b.booking_id DESC
    `
    );

    const bookings = rows.map((b) => ({
      booking_id: b.booking_id,
      booking_date: b.booking_date_ymd,        // 👈 fixed
      booking_status: "Waiting",
      room_name: b.room_name,
      slot_id: b.slot_id,
      start_time: String(b.start_time).slice(0, 5),
      end_time: String(b.end_time).slice(0, 5),
      booked_by_name: `${b.student_first}${
        b.student_last ? " " + b.student_last : ""
      }`,
    }));

    res.json({ ok: true, bookings });
  } catch (e) {
    console.error("lecturer pending error:", e);
    res.status(500).json({ error: "Database error" });
  }
});

app.get("/lecturer/bookings/history", ensureLecturer, async (req, res) => {
  try {
    const rows = await q(
      `
      SELECT
        b.booking_id,
        DATE_FORMAT(b.booking_date, '%Y-%m-%d') AS booking_date_ymd,
        b.booking_status,
        b.reason AS reject_reason,
        b.slot_id,
        r.room_name,
        t.start_time,
        t.end_time,
        u.first_name AS student_first,
        u.last_name  AS student_last,
        a.first_name AS approver_first,
        a.last_name  AS approver_last
      FROM booking b
      JOIN room r       ON r.room_id = b.room_id
      JOIN time_slot t  ON t.slot_id = b.slot_id
      JOIN users u      ON u.user_id = b.user_id
      JOIN users a      ON a.user_id = b.approver_id
      WHERE b.approver_id = ?
        AND b.booking_status IN ('Approved','Rejected')
      ORDER BY b.booking_id DESC
    `,
      [req.user.id]
    );

    const bookings = rows.map((b) => ({
      booking_id: b.booking_id,
      booking_date: b.booking_date_ymd,        // 👈 fixed
      booking_status: b.booking_status,        // Approved | Rejected
      reject_reason: b.reject_reason || "",
      room_name: b.room_name,
      slot_id: b.slot_id,
      start_time: String(b.start_time).slice(0, 5),
      end_time: String(b.end_time).slice(0, 5),
      booked_by_name: `${b.student_first}${
        b.student_last ? " " + b.student_last : ""
      }`,
      approver_name: `${b.approver_first}${
        b.approver_last ? " " + b.approver_last : ""
      }`,
    }));

    res.json({ ok: true, bookings });
  } catch (e) {
    console.error("lecturer history error:", e);
    res.status(500).json({ error: "Database error" });
  }
});

app.post("/lecturer/bookings/:id/approve",ensureLecturer, async (req, res) => {
    try {
      const id = Number(req.params.id) || 0;
      const rows = await q(
        "SELECT booking_id FROM booking WHERE booking_id = ? AND booking_status = 'Waiting' LIMIT 1",
        [id]
      );
      if (!rows.length)
        return res
          .status(404)
          .json({ error: "Booking not found or not Waiting" });

      await q(
        `
        UPDATE booking
        SET booking_status = 'Approved',
            approver_id = ?,
            reason = NULL
        WHERE booking_id = ?
      `,
        [req.user.id, id]
      );

      res.json({ ok: true });
    } catch (e) {
      console.error("approve error:", e);
      res.status(500).json({ error: "Database error" });
    }
  }
);

app.post("/lecturer/bookings/:id/reject", ensureLecturer, async (req, res) => {
  try {
    const id = Number(req.params.id) || 0;
    const reason = (req.body && req.body.reason ? String(req.body.reason) : "").trim();
    if (!reason) return res.status(400).json({ error: "Reason required" });

    const rows = await q(
      "SELECT booking_id FROM booking WHERE booking_id = ? AND booking_status = 'Waiting' LIMIT 1",
      [id]
    );
    if (!rows.length)
      return res.status(404).json({ error: "Booking not found or not Waiting" });

    await q(
      `
      UPDATE booking
      SET booking_status = 'Rejected',
          approver_id = ?,
          reason = ?
      WHERE booking_id = ?
    `,
      [req.user.id, reason, id]
    );

    res.json({ ok: true });
  } catch (e) {
    console.error("reject error:", e);
    res.status(500).json({ error: "Database error" });
  }
});





























// ============================================================================
// STAFF endpoints (pending/history/rooms list/toggle/edit/create)  — with capacity
// ============================================================================
const ensureStaff = [requireAuth, requireRole("staff")];

app.get("/staff/bookings/pending", ensureStaff, async (_req, res) => {
  try {
    const rows = await q(`
      SELECT
        b.booking_id,
        DATE_FORMAT(b.booking_date, '%Y-%m-%d') AS booking_date_ymd,
        b.booking_status,
        b.user_id,
        b.slot_id,
        r.room_name,
        t.start_time,
        t.end_time,
        u.first_name AS student_first,
        u.last_name  AS student_last
      FROM booking b
      JOIN room r      ON r.room_id = b.room_id
      JOIN time_slot t ON t.slot_id = b.slot_id
      JOIN users u     ON u.user_id = b.user_id
      WHERE b.booking_status = 'Waiting'
      ORDER BY b.booking_id DESC
    `);

    const bookings = rows.map((b) => ({
      booking_id: b.booking_id,
      booking_date: b.booking_date_ymd,        // 👈 fixed
      booking_status: "Waiting",
      room_name: b.room_name,
      slot_id: b.slot_id,
      start_time: String(b.start_time).slice(0, 5),
      end_time: String(b.end_time).slice(0, 5),
      booked_by_name: `${b.student_first}${
        b.student_last ? " " + b.student_last : ""
      }`,
    }));
    res.json({ ok: true, bookings });
  } catch (e) {
    console.error("staff pending error:", e);
    res.status(500).json({ error: "Database error" });
  }
});

app.get("/staff/bookings/history", ensureStaff, async (_req, res) => {
  try {
    const rows = await q(`
      SELECT
        b.booking_id,
        DATE_FORMAT(b.booking_date, '%Y-%m-%d') AS booking_date_ymd,
        b.booking_status,
        b.reason AS reject_reason,
        b.slot_id,
        r.room_name,
        t.start_time,
        t.end_time,
        u.first_name AS student_first,
        u.last_name  AS student_last,
        a.first_name AS approver_first,
        a.last_name  AS approver_last
      FROM booking b
      JOIN room r       ON r.room_id = b.room_id
      JOIN time_slot t  ON t.slot_id = b.slot_id
      JOIN users u      ON u.user_id = b.user_id           -- student
      LEFT JOIN users a ON a.user_id = b.approver_id        -- may be null
      WHERE b.booking_status IN ('Approved','Rejected')
      ORDER BY b.booking_id DESC
    `);

    const bookings = rows.map((b) => ({
      booking_id: b.booking_id,
      booking_date: b.booking_date_ymd,        // 👈 fixed
      booking_status: b.booking_status,
      reject_reason: b.reject_reason || "",
      room_name: b.room_name,
      slot_id: b.slot_id,
      start_time: String(b.start_time).slice(0, 5),
      end_time: String(b.end_time).slice(0, 5),
      booked_by_name: `${b.student_first}${
        b.student_last ? " " + b.student_last : ""
      }`,
      approver_name: b.approver_first
        ? `${b.approver_first}${
            b.approver_last ? " " + b.approver_last : ""
          }`
        : "",
    }));
    res.json({ ok: true, bookings });
  } catch (e) {
    console.error("staff history error:", e);
    res.status(500).json({ error: "Database error" });
  }
});

// GET /staff/rooms/management
app.get('/staff/rooms/management', ensureStaff, async (req, res) => {
  try {
    const rows = await q(`
      SELECT
        r.room_id          AS id,
        r.room_name        AS name,
        r.room_status,
        r.description,
        r.image,
        COALESCE(r.capacity,0) AS capacity,
        (
          SELECT COUNT(*)
          FROM booking b
          WHERE b.room_id = r.room_id
            AND b.booking_status IN ('Waiting','Approved')
            AND b.booking_date >= CURDATE()
        ) AS active_bookings
      FROM room r
      ORDER BY r.room_name ASC
    `);

    const rooms = rows.map(r => ({
      id: r.id,
      name: r.name,
      description: r.description,
      capacity: Number(r.capacity) || 0,
      image_url: r.image ? `${PUBLIC_BASE}/uploads/${encodeURIComponent(r.image)}` : '',
      room_status: r.room_status,          // 1 enabled, 0 disabled
      active_bookings: Number(r.active_bookings) || 0,
    }));

    res.json({ ok: true, rooms });
  } catch (e) {
    console.error('staff rooms management error:', e);
    res.status(500).json({ error: 'Database error' });
  }
});

// Toggle room enabled/disabled (block disable if active bookings exist from today onward)
app.post("/staff/rooms/:id/toggle",
  ensureStaff,
  async (req, res) => {
    try {
      const roomId = Number(req.params.id) || 0;
      const rooms = await q(
        "SELECT room_status FROM room WHERE room_id = ? LIMIT 1",
        [roomId]
      );
      if (!rooms.length) return res.status(404).json({ error: "Room not found" });

      const current = Number(rooms[0].room_status) === 1;
      const wantDisable = current === true;
      const wantEnable = current === false;

      if (wantDisable) {
        const today = new Date().toISOString().slice(0, 10);
        const active = await q(
          `
          SELECT 1
          FROM booking
          WHERE room_id = ?
            AND booking_status IN ('Waiting','Approved')
            AND booking_date >= ?
          LIMIT 1
        `,
          [roomId, today]
        );
        if (active.length) {
          return res
            .status(409)
            .json({ error: "Cannot disable this room while it has active bookings." });
        }
        await q("UPDATE room SET room_status = 0 WHERE room_id = ?", [roomId]);
        return res.json({ ok: true, room_status: 0 });
      }

      if (wantEnable) {
        await q("UPDATE room SET room_status = 1 WHERE room_id = ?", [roomId]);
        return res.json({ ok: true, room_status: 1 });
      }

      return res.json({ ok: true, room_status: current ? 1 : 0 });
    } catch (e) {
      console.error("staff toggle error:", e);
      res.status(500).json({ error: "Database error" });
    }
  }
);

// POST /staff/rooms/:id/edit   { name, description, capacity }
app.post('/staff/rooms/:id/edit', [requireAuth, requireRole('staff')], async (req, res) => {
  try {
    const roomId = Number(req.params.id) || 0;
    const { name, description, capacity } = req.body || {};

    if (!roomId) return res.status(400).json({ error: 'Invalid room id' });
    if (!name || !String(name).trim()) {
      return res.status(400).json({ error: 'Room name is required' });
    }
    const capNum = Number.parseInt(capacity, 10);
    if (Number.isNaN(capNum) || capNum < 0) {
      return res.status(400).json({ error: 'Capacity must be a non-negative integer' });
    }

    const rows = await q('SELECT room_id FROM room WHERE room_id = ? LIMIT 1', [roomId]);
    if (!rows.length) return res.status(404).json({ error: 'Room not found' });

    await q(
      'UPDATE room SET room_name = ?, description = ?, capacity = ? WHERE room_id = ?',
      [String(name).trim(), String(description || '').trim(), capNum, roomId]
    );

    const updated = await q(`
      SELECT room_id   AS id,
             room_name AS name,
             COALESCE(description,'') AS description,
             COALESCE(image,'')       AS image_file,
             COALESCE(capacity,0)     AS capacity,
             room_status
      FROM room WHERE room_id = ? LIMIT 1
    `, [roomId]);

    const r = updated[0];
    return res.json({
      ok: true,
      room: {
        id: r.id,
        name: r.name,
        description: r.description,
        capacity: Number(r.capacity) || 0,
        image_url: r.image_file ? `${PUBLIC_BASE}/uploads/${encodeURIComponent(r.image_file)}` : '',
        room_status: Number(r.room_status),
      }
    });
  } catch (e) {
    console.error('staff edit room error:', e);
    res.status(500).json({ error: 'Database error' });
  }
});

// Upload/replace room image (kept same)
app.post("/rooms/:id/image", upload.single("image"), async (req, res) => {
  try {
    const id = req.params.id;
    if (!req.file) return res.status(400).send("No file uploaded");

    await q("UPDATE room SET image = ? WHERE room_id = ?", [
      req.file.filename,
      id,
    ]);

    res.json({
      ok: true,
      filename: req.file.filename,
      url: `${PUBLIC_BASE}/uploads/${encodeURIComponent(req.file.filename)}`,
    });
  } catch (e) {
    console.error("upload error:", e);
    res.status(500).send("Upload failed");
  }
});

// ===== STAFF: create room =====
app.post('/staff/rooms/create', [requireAuth, requireRole('staff')], async (req, res) => {
  try {
    const { name, capacity, description } = req.body || {};
    const roomName = String(name || '').trim();
    const cap = Number.isFinite(Number(capacity)) ? Number(capacity) : 0;
    const desc = String(description || '').trim();

    if (!roomName) return res.status(400).json({ error: 'Room name is required' });
    if (cap < 0)     return res.status(400).json({ error: 'Capacity must be >= 0' });

    const dup = await q('SELECT room_id FROM room WHERE room_name = ? LIMIT 1', [roomName]);
    if (dup.length) return res.status(409).json({ error: 'Room name already exists' });

    // image is NOT NULL in your schema, so use '' as placeholder
    const ins = await q(
      `INSERT INTO room (room_name, room_status, capacity, description, image)
       VALUES (?, 1, ?, ?, '')`,
      [roomName, cap, desc]
    );

    const newId = Number(ins.insertId);

    // 👇 Add id at top-level
    return res.status(201).json({
      ok: true,
      id: newId,
      room: {
        id: newId,
        name: roomName,
        capacity: cap,
        description: desc,
        room_status: 1,
        image_url: '',
      }
    });
  } catch (e) {
    console.error('staff create room error:', e);
    return res.status(500).json({ error: 'Database error' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

module.exports = app;