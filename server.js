import express from "express";
import cors from "cors";
import mysql from "mysql2/promise";

const app = express();
app.use(cors());

const {
  DB_HOST,
  DB_PORT,
  DB_USER,
  DB_PASSWORD,
  DB_NAME,
  DB_CA,
  API_KEY,
  PORT = 3000,
} = process.env;

// Conexión a MySQL (Aiven exige SSL)
const pool = mysql.createPool({
  host: DB_HOST,
  port: Number(DB_PORT),
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_NAME,
  waitForConnections: true,
  connectionLimit: 5,
  ssl: DB_CA
    ? { ca: DB_CA.replace(/\\n/g, "\n"), rejectUnauthorized: true }
    : { rejectUnauthorized: false },
});

// Protección simple con clave (cabecera x-api-key)
function requireKey(req, res, next) {
  if (!API_KEY) return next(); // si no configuras clave, queda abierta
  if (req.get("x-api-key") !== API_KEY) {
    return res.status(401).json({ error: "No autorizado" });
  }
  next();
}

const COLUMNAS =
  "id, nombre, descripcion_historica, categoria, direccion, imagen_url";

app.get("/", (req, res) => res.json({ ok: true, servicio: "API Ciénaga" }));

// Lista todos los sitios (opcional: ?categoria=Plaza)
app.get("/sitios", requireKey, async (req, res) => {
  try {
    const { categoria } = req.query;
    const [rows] = categoria
      ? await pool.query(
          `SELECT ${COLUMNAS} FROM sitios_cienaga WHERE categoria = ? ORDER BY nombre`,
          [categoria]
        )
      : await pool.query(
          `SELECT ${COLUMNAS} FROM sitios_cienaga ORDER BY nombre`
        );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al consultar la base de datos" });
  }
});

// Un solo sitio por id
app.get("/sitios/:id", requireKey, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT ${COLUMNAS} FROM sitios_cienaga WHERE id = ?`,
      [req.params.id]
    );
    if (rows.length === 0) {
      return res.status(404).json({ error: "Sitio no encontrado" });
    }
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al consultar la base de datos" });
  }
});

app.listen(PORT, () => console.log(`API escuchando en el puerto ${PORT}`));
