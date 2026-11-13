
import express from "express";
import cors from "cors";
import mysql from "mysql2/promise";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const app = express();
app.use(cors());
app.use(express.json());

const {
  DB_HOST,
  DB_PORT,
  DB_USER,
  DB_PASSWORD,
  DB_NAME,
  DB_CA,
  API_KEY,
  JWT_SECRET,
  PORT = 3000,
} = process.env;

if (!JWT_SECRET) {
  console.error("Falta la variable de entorno JWT_SECRET");
  process.exit(1);
}

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

// Protección mediante clave API
function requireKey(req, res, next) {
  if (!API_KEY) return next();

  if (req.get("x-api-key") !== API_KEY) {
    return res.status(401).json({ error: "No autorizado" });
  }

  next();
}

// Autenticación individual mediante token
// Power Apps enviará el token en x-user-token
function requireAuth(req, res, next) {
  const token = (req.get("x-user-token") || "").replace(/^Bearer\s+/i, "");

  try {
    req.userId = jwt.verify(token, JWT_SECRET).id;
    next();
  } catch {
    res.status(401).json({
      error: "Sesión no válida, inicia sesión de nuevo",
    });
  }
}

// Hash de relleno para proteger el inicio de sesión
const HASH_RELLENO = bcrypt.hashSync("relleno-no-valido", 10);

// Consulta base de sitios
const SELECT_SITIOS = `
  SELECT s.id, s.nombre, s.descripcion_historica,
         c.nombre AS categoria, s.direccion, s.imagen_url
  FROM sitios_cienaga s
  LEFT JOIN categorias c ON c.id_cat = s.id_cat
`;

app.get("/", (req, res) =>
  res.json({ ok: true, servicio: "API Ciénaga" })
);

// ---------- SITIOS ----------

// Listar sitios
app.get("/sitios", requireKey, async (req, res) => {
  try {
    const { categoria } = req.query;

    const [rows] = categoria
      ? await pool.query(
          `${SELECT_SITIOS} WHERE c.nombre = ? ORDER BY s.nombre`,
          [categoria]
        )
      : await pool.query(`${SELECT_SITIOS} ORDER BY s.nombre`);

    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Error al consultar la base de datos",
    });
  }
});

// Obtener un sitio por ID
app.get("/sitios/:id", requireKey, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `${SELECT_SITIOS} WHERE s.id = ?`,
      [req.params.id]
    );

    if (rows.length === 0) {
      return res.status(404).json({
        error: "Sitio no encontrado",
      });
    }

    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Error al consultar la base de datos",
    });
  }
});

// Listar categorías
app.get("/categorias", requireKey, async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT id_cat, nombre FROM categorias ORDER BY nombre"
    );

    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Error al consultar la base de datos",
    });
  }
});

// ---------- USUARIOS ----------

// Registrar usuario
app.post("/registro", requireKey, async (req, res) => {
  try {
    const { usuario, clave } = req.body || {};
    const nombre = typeof usuario === "string" ? usuario.trim() : "";

    if (!nombre || typeof clave !== "string" || !clave) {
      return res.status(400).json({
        error: "Faltan usuario o contraseña",
      });
    }

    if (nombre.length > 50) {
      return res.status(400).json({
        error: "El usuario es demasiado largo (máximo 50)",
      });
    }

    if (clave.length < 6 || clave.length > 72) {
      return res.status(400).json({
        error: "La contraseña debe tener entre 6 y 72 caracteres",
      });
    }

    const hash = await bcrypt.hash(clave, 10);

    await pool.query(
      "INSERT INTO login (usuario, clave_hash) VALUES (?, ?)",
      [nombre, hash]
    );

    res.status(201).json({
      ok: true,
      mensaje: "Usuario registrado",
    });
  } catch (err) {
    if (err.code === "ER_DUP_ENTRY") {
      return res.status(409).json({
        error: "El usuario ya existe",
      });
    }

    console.error(err);
    res.status(500).json({
      error: "Error al registrar el usuario",
    });
  }
});

// Iniciar sesión
app.post("/login", requireKey, async (req, res) => {
  try {
    const { usuario, clave } = req.body || {};
    const nombre = typeof usuario === "string" ? usuario.trim() : "";

    if (!nombre || typeof clave !== "string" || !clave || clave.length > 72) {
      return res.status(400).json({
        error: "Faltan usuario o contraseña",
      });
    }

    const [rows] = await pool.query(
      "SELECT id, usuario, clave_hash FROM login WHERE usuario = ?",
      [nombre]
    );

    const hash = rows.length ? rows[0].clave_hash : HASH_RELLENO;
    const coincide = await bcrypt.compare(clave, hash);

    if (!rows.length || !coincide) {
      return res.status(401).json({
        error: "Usuario o contraseña incorrectos",
      });
    }

    const token = jwt.sign(
      { id: rows[0].id },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      ok: true,
      id: rows[0].id,
      usuario: rows[0].usuario,
      token,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Error al iniciar sesión",
    });
  }
});

// ---------- FAVORITOS ----------

// Consultar favoritos del usuario autenticado
app.get("/mis-favoritos", requireKey, requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `${SELECT_SITIOS}
       JOIN favoritos f ON f.id_sitio = s.id
       WHERE f.id_usuario = ?
       ORDER BY s.nombre`,
      [req.userId]
    );

    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Error al consultar favoritos",
    });
  }
});

// Agregar favorito
app.post("/favoritos", requireKey, requireAuth, async (req, res) => {
  try {
    const idSitio = Number((req.body || {}).id_sitio);

    if (!Number.isInteger(idSitio) || idSitio <= 0) {
      return res.status(400).json({
        error: "id_sitio no válido",
      });
    }

    await pool.query(
      "INSERT IGNORE INTO favoritos (id_usuario, id_sitio) VALUES (?, ?)",
      [req.userId, idSitio]
    );

    res.status(201).json({ ok: true });
  } catch (err) {
    if (err.code === "ER_NO_REFERENCED_ROW_2") {
      return res.status(404).json({
        error: "Sitio no encontrado",
      });
    }

    console.error(err);
    res.status(500).json({
      error: "Error al guardar el favorito",
    });
  }
});

// Eliminar favorito del usuario autenticado
app.delete(
  "/favoritos/:id_sitio",
  requireKey,
  requireAuth,
  async (req, res) => {
    try {
      await pool.query(
        "DELETE FROM favoritos WHERE id_usuario = ? AND id_sitio = ?",
        [req.userId, req.params.id_sitio]
      );

      res.json({ ok: true });
    } catch (err) {
      console.error(err);
      res.status(500).json({
        error: "Error al quitar el favorito",
      });
    }
  }
);

// ---------- COMENTARIOS ----------

// Listar comentarios públicos de un sitio
app.get("/sitios/:id/comentarios", requireKey, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT c.id, c.texto, c.creado_en, l.usuario
       FROM comentarios c
       JOIN login l ON l.id = c.id_usuario
       WHERE c.id_sitio = ?
       ORDER BY c.creado_en DESC`,
      [req.params.id]
    );

    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Error al consultar comentarios",
    });
  }
});

// Publicar comentario
app.post(
  "/sitios/:id/comentarios",
  requireKey,
  requireAuth,
  async (req, res) => {
    try {
      const texto =
        typeof (req.body || {}).texto === "string"
          ? req.body.texto.trim()
          : "";

      if (!texto) {
        return res.status(400).json({
          error: "El comentario está vacío",
        });
      }

      if (texto.length > 500) {
        return res.status(400).json({
          error: "El comentario es demasiado largo (máximo 500)",
        });
      }

      await pool.query(
        "INSERT INTO comentarios (id_sitio, id_usuario, texto) VALUES (?, ?, ?)",
        [req.params.id, req.userId, texto]
      );

      res.status(201).json({ ok: true });
    } catch (err) {
      if (err.code === "ER_NO_REFERENCED_ROW_2") {
        return res.status(404).json({
          error: "Sitio no encontrado",
        });
      }

      console.error(err);
      res.status(500).json({
        error: "Error al guardar el comentario",
      });
    }
  }
);

// Eliminar únicamente los comentarios propios
app.delete(
  "/comentarios/:id",
  requireKey,
  requireAuth,
  async (req, res) => {
    try {
      await pool.query(
        "DELETE FROM comentarios WHERE id = ? AND id_usuario = ?",
        [req.params.id, req.userId]
      );

      res.json({ ok: true });
    } catch (err) {
      console.error(err);
      res.status(500).json({
        error: "Error al borrar el comentario",
      });
    }
  }
);

// ---------- INICIAR SERVIDOR ----------

app.listen(PORT, () => {
  console.log(`API escuchando en el puerto ${PORT}`);
});
