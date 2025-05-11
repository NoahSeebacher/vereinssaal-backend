/**************************************************
 * server.js
 **************************************************/
const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(bodyParser.json());
app.use(cors());

const SECRET_KEY = 'your_super_secret_key';

// -- MySQL-Verbindung einrichten --
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
});

db.connect((err) => {
  if (err) {
    console.error('❌ Datenbankverbindung fehlgeschlagen:', err.stack);
    return;
  }
  console.log('✅ Mit der Datenbank verbunden.');
});

const promiseDB = db.promise();

// -- LOGIN ENDPOINT --
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  // Now include u_is_staff in the SELECT statement
  const query = `SELECT u_id, u_password, u_is_admin, u_is_staff FROM users WHERE LOWER(u_email) = LOWER(?)`;

  db.query(query, [email.trim()], async (err, results) => {
    if (err) {
      console.error('❌ Fehler bei der Datenbankabfrage:', err);
      return res.status(500).json({ success: false, message: 'Interner Serverfehler' });
    }

    if (results.length === 0) {
      return res.status(404).json({ success: false, message: 'Benutzer nicht gefunden' });
    }

    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.u_password);
    
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Falsches Passwort' });
    }

    // Create token including u_is_admin and u_is_staff
    const token = jwt.sign({ 
      userId: user.u_id, 
      u_is_admin: user.u_is_admin, 
      u_is_staff: user.u_is_staff  
    }, SECRET_KEY, { expiresIn: '2h' });
    res.status(200).json({ 
      success: true, 
      message: 'Login erfolgreich', 
      token, 
      userId: user.u_id 
    });
  });
});


// -- REGISTRIERUNG --
app.post('/api/signup', async (req, res) => {
  const { first_name, last_name, phone, email, password, tax_nr } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 6);
    const query = `
      INSERT INTO users (u_first_name, u_last_name, u_phone, u_email, u_password, u_tax_nr)
      VALUES (?, ?, ?, ?, ?, ?)
    `;
    
    db.query(query, [first_name, last_name, phone, email, hashedPassword, tax_nr], (err, result) => {
      if (err) {
        console.error('❌ Fehler beim Registrieren:', err);
        return res.status(500).json({ success: false, message: 'Benutzerregistrierung fehlgeschlagen.' });
      }
      res.status(200).json({ success: true, message: 'Benutzer erfolgreich registriert.' });
    });
  } catch (error) {
    console.error('❌ Fehler beim Hashen des Passworts:', error);
    res.status(500).json({ success: false, message: 'Fehler bei der Verarbeitung der Anfrage.' });
  }
});

// -- HILFSFUNKTION: ISO -> MySQL DATETIME Format --
function toMySQLDateTime(isoString) {
  const dateObj = new Date(isoString);

  // Beispiel: "2025-02-09T07:30:00.000Z" -> "2025-02-09 07:30:00"
  const year = dateObj.getFullYear();
  const month = String(dateObj.getMonth() + 1).padStart(2, '0');
  const day = String(dateObj.getDate()).padStart(2, '0');
  const hours = String(dateObj.getHours()).padStart(2, '0');
  const minutes = String(dateObj.getMinutes()).padStart(2, '0');
  const seconds = String(dateObj.getSeconds()).padStart(2, '0');

  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
}

// -- RESERVIERUNG SPEICHERN --
app.post('/api/reservations', async (req, res) => {
  try {
    const {
      startTime, endTime, hall,
      details, reason, userId, extras = [],
      recurrence = {}
    } = req.body;

    if (!startTime || !endTime || !hall || !reason) {
      return res.status(400).json({
        success: false,
        message: 'Fehlende Pflichtangaben in der Reservierung.'
      });
    }

    const finalUserId = userId || 1;
    const interval = recurrence.interval || 'none';
    const count    = parseInt(recurrence.count, 10) || 1;

    // Helfer: ISO → MySQL DATETIME
    function toMySQLDate(iso) {
      const d = new Date(iso);
      return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')} ` +
             `${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}:${String(d.getSeconds()).padStart(2,'0')}`;
    }

    // SQL und Extras-Mapping
    const sql = `
      INSERT INTO reservations (
        u_id, h_id, r_start_datetime, r_end_datetime,
        r_purpose, r_other_details,
        bar, kitchen, wc, microphone, laser_pointer, projector,
        seating, folding_tables, standing_tables, stage_lighting,
        lighting_console, partition_elements, plates_and_cutlery
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    // Platzhalter-Array (Start/End kommen später per splice)
    const baseParams = [
      finalUserId,
      hall,
      /* START_DATETIME */,
      /* END_DATETIME */,
      reason,
      details || null,
      extras.includes('Bar')               ? 1 : 0,
      extras.includes('Küche')             ? 1 : 0,
      extras.includes('WC')                ? 1 : 0,
      extras.includes('Mikrophon')         ? 1 : 0,
      extras.includes('Laserpointer')      ? 1 : 0,
      extras.includes('Projektor')         ? 1 : 0,
      extras.includes('Bestuhlung')        ? 1 : 0,
      extras.includes('Klapptische')       ? 1 : 0,
      extras.includes('Stehtische')        ? 1 : 0,
      extras.includes('Bühnenlichtanlage') ? 1 : 0,
      extras.includes('Lichtmischpult')    ? 1 : 0,
      extras.includes('Abtrennelemente (durchsichtig)') ? 1 : 0,
      extras.includes('Teller & Besteck')  ? 1 : 0
    ];

    const insertedIds = [];
    const start0 = new Date(startTime);
    const end0   = new Date(endTime);

    for (let i = 0; i < count; i++) {
      // Wiederholungsrechner
      const occStart = new Date(start0);
      const occEnd   = new Date(end0);
      if (interval === 'daily') {
        occStart.setDate(occStart.getDate() + i);
        occEnd.setDate(occEnd.getDate() + i);
      } else if (interval === 'weekly') {
        occStart.setDate(occStart.getDate() + 7 * i);
        occEnd.setDate(occEnd.getDate() + 7 * i);
      } else if (interval === 'monthly') {
        occStart.setMonth(occStart.getMonth() + i);
        occEnd.setMonth(occEnd.getMonth() + i);
      }
      const startSQL = toMySQLDate(occStart.toISOString());
      const endSQL   = toMySQLDate(occEnd.toISOString());

      const params = [...baseParams];
      params.splice(2, 2, startSQL, endSQL);

      const [result] = await promiseDB.execute(sql, params);
      insertedIds.push(result.insertId);
    }

    return res.status(201).json({
      success: true,
      reservationIds: insertedIds
    });

  } catch (err) {
    console.error('❌ Fehler beim Speichern der Reservierung:', err);
    return res.status(500).json({
      success: false,
      message: 'Fehler beim Speichern der Reservierung.',
      error: err.message
    });
  }
});

// -- RESERVIERUNGEN ABRUFEN --
app.get('/api/reservations', (req, res) => {
  const sql = `
   SELECT
  r_id AS reservationId,
  r_start_datetime AS start,
  r_end_datetime AS end,
  h_id AS hall,
  r_purpose AS reason,
  r_other_details AS details,
  r_confirmed AS confirmed,
  bar,
  kitchen,
  wc,
  microphone,
  laser_pointer,
  projector,
  seating,
  folding_tables,
  standing_tables,
  stage_lighting,
  lighting_console,
  partition_elements,
  plates_and_cutlery,
  CONCAT(users.u_first_name, ' ', users.u_last_name) AS title
FROM reservations
JOIN users ON reservations.u_id = users.u_id
  `;

  db.query(sql, (err, results) => {
    if (err) {
      console.error('❌ Fehler beim Abrufen der Reservierungen:', err);
      return res.status(500).json({ success: false, message: 'Fehler beim Abrufen der Reservierungen.', error: err });
    }

    console.log('✅ Reservierungen erfolgreich geladen:', results);
    res.status(200).json(results);
  });
});


// -- RESERVIERUNG BESTÄTIGEN/ABLEHNEN --
app.put('/api/reservations/:id/confirm', (req, res) => {
  const reservationId = req.params.id;
  const { confirmed } = req.body; // true = accepted, false = declined
  
  const query = 'UPDATE reservations SET r_confirmed = ? WHERE r_id = ?';
  db.query(query, [confirmed, reservationId], (err, result) => {
    if (err) {
      console.error("❌ Fehler beim Aktualisieren der Bestätigung:", err);
      return res.status(500).json({ success: false, message: 'Fehler beim Aktualisieren der Bestätigung.', error: err });
    }
    res.status(200).json({ success: true, message: 'Bestätigung aktualisiert.' });
  });
});

// -- RESERVIERUNG LÖSCHEN --
app.delete('/api/reservations/:id', (req, res) => {
  const reservationId = req.params.id;
  const query = `DELETE FROM reservations WHERE r_id = ?`;
  db.query(query, [reservationId], (err, result) => {
    if (err) {
      console.error('❌ Fehler beim Löschen der Reservierung:', err);
      return res.status(500).json({ success: false, message: 'Fehler beim Löschen der Reservierung.' });
    }
    res.status(200).json({ success: true, message: 'Reservierung erfolgreich gelöscht.' });
  });
});



// -- GET USER DATA --
app.get('/api/users/:id', (req, res) => {
  const userId = req.params.id;
  const query = `
    SELECT 
      u_id AS userId,
      u_first_name AS first_name,
      u_last_name AS last_name,
      u_phone AS phone,
      u_email AS email,
      u_tax_nr AS tax_nr,
      u_is_admin AS is_admin
    FROM users
    WHERE u_id = ?
  `;
  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('❌ Fehler beim Abrufen der Benutzerdaten:', err);
      return res.status(500).json({ success: false, message: 'Fehler beim Abrufen der Benutzerdaten.' });
    }
    if (results.length === 0) {
      return res.status(404).json({ success: false, message: 'Benutzer nicht gefunden.' });
    }
    res.status(200).json(results[0]);
  });
});

// -- USER PROFILE UPDATE --
app.put('/api/users/:id', (req, res) => {
  const userId = req.params.id;
  const { first_name, last_name, phone, email, tax_nr } = req.body;
  const query = `
    UPDATE users 
    SET u_first_name = ?, u_last_name = ?, u_phone = ?, u_email = ?, u_tax_nr = ?
    WHERE u_id = ?
  `;
  db.query(query, [first_name, last_name, phone, email, tax_nr, userId], (err, result) => {
    if (err) {
      console.error('❌ Fehler beim Aktualisieren des Benutzerprofils:', err);
      return res.status(500).json({ success: false, message: 'Fehler beim Aktualisieren des Benutzerprofils.' });
    }
    res.status(200).json({ success: true, message: 'Profil erfolgreich aktualisiert.' });
  });
});


// -- EMAIL CHECK ROUTE --
app.post('/api/check-email', (req, res) => {
  const { email } = req.body;
  // Kleiner Schutz: E-Mail trimmen und in Kleinschreibung
  const lowerEmail = email.trim().toLowerCase();
  const checkQuery = `
    SELECT 1 FROM users
    WHERE LOWER(u_email) = ?
    LIMIT 1
  `;
  db.query(checkQuery, [lowerEmail], (err, results) => {
    if (err) {
      console.error('❌ Fehler bei der Emailprüfung:', err);
      return res.status(500).json({ success: false, message: 'Interner Serverfehler' });
    }
    const exists = results.length > 0;
    // Falls E-Mail schon belegt ist, exists = true
    res.status(200).json({ exists });
  });
});

// -- SERVER STARTEN --
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Server läuft auf Port ${PORT}`);
});


