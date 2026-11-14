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
  console.warn("Falta la variable JWT_SECRET: el inicio de sesión no va a funcionar.");
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

// Hash de relleno: se compara cuando el usuario no existe (evita revelar usuarios por tiempo)
const HASH_RELLENO = bcrypt.hashSync("relleno-no-valido", 10);

// Protección 1: clave de la API (cabecera x-api-key)
function requireKey(req, res, next) {
  if (!API_KEY) return next(); // si no configuras clave, queda abierta
  if (req.get("x-api-key") !== API_KEY) {
    return res.status(401).json({ error: "No autorizado" });
  }
  next();
}

// Protección 2: sesión del usuario (cabecera x-token).
// El id del usuario sale del token, nunca de lo que mande la app.
function requireUser(req, res, next) {
  const token = req.get("x-token");
  if (!token || !JWT_SECRET) {
    return res.status(401).json({ error: "Debes iniciar sesión" });
  }
  try {
    const datos = jwt.verify(token, JWT_SECRET);
    req.userId = datos.id;
    req.usuario = datos.usuario;
    next();
  } catch {
    res.status(401).json({ error: "Sesión inválida o vencida" });
  }
}

const esEntero = (v) => /^\d+$/.test(String(v));
const errorServidor = (res, err, mensaje) => {
  console.error(err);
  res.status(500).json({ error: mensaje });
};

// Columna de sitios_cienaga que apunta a la tabla categorias (llave foránea)
const FK_CATEGORIA = "id_cat";

// Los sitios con el NOMBRE de su categoría. Se sigue llamando "categoria" para que la app no cambie.
const SELECT_SITIOS = `SELECT s.id, s.nombre, s.descripcion_historica,
  c.nombre AS categoria, s.direccion, s.imagen_url
  FROM sitios_cienaga s
  LEFT JOIN categorias c ON c.id_cat = s.${FK_CATEGORIA}`;

app.get("/", (req, res) => res.json({ ok: true, servicio: "API Ciénaga" }));

// ---------------------------- SITIOS ----------------------------

// Lista todos los sitios (opcional: ?categoria=Plaza)
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
    errorServidor(res, err, "Error al consultar la base de datos");
  }
});

// Un solo sitio por id
app.get("/sitios/:id", requireKey, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `${SELECT_SITIOS} WHERE s.id = ?`,
      [req.params.id]
    );
    if (rows.length === 0) {
      return res.status(404).json({ error: "Sitio no encontrado" });
    }
    res.json(rows[0]);
  } catch (err) {
    errorServidor(res, err, "Error al consultar la base de datos");
  }
});

// ---------------------------- USUARIOS ----------------------------

// Registro: guarda usuario + contraseña CIFRADA (hash) en la tabla login
app.post("/registro", requireKey, async (req, res) => {
  try {
    const { usuario, clave } = req.body || {};
    const nombre = typeof usuario === "string" ? usuario.trim() : "";

    if (!nombre || typeof clave !== "string" || !clave) {
      return res.status(400).json({ error: "Faltan usuario o contraseña" });
    }
    if (nombre.length > 50) {
      return res.status(400).json({ error: "El usuario es demasiado largo (máximo 50)" });
    }
    if (clave.length < 6 || clave.length > 72) {
      return res.status(400).json({ error: "La contraseña debe tener entre 6 y 72 caracteres" });
    }

    const hash = await bcrypt.hash(clave, 10);
    await pool.query(
      "INSERT INTO login (usuario, clave_hash) VALUES (?, ?)",
      [nombre, hash]
    );
    res.status(201).json({ ok: true, mensaje: "Usuario registrado" });
  } catch (err) {
    if (err.code === "ER_DUP_ENTRY") {
      return res.status(409).json({ error: "El usuario ya existe" });
    }
    errorServidor(res, err, "Error al registrar el usuario");
  }
});

// Inicio de sesión: compara la contraseña con el hash y entrega un token
app.post("/login", requireKey, async (req, res) => {
  try {
    if (!JWT_SECRET) {
      return res.status(500).json({ error: "Falta configurar JWT_SECRET en el servidor" });
    }
    const { usuario, clave } = req.body || {};
    const nombre = typeof usuario === "string" ? usuario.trim() : "";

    if (!nombre || typeof clave !== "string" || !clave || clave.length > 72) {
      return res.status(400).json({ error: "Faltan usuario o contraseña" });
    }

    const [rows] = await pool.query(
      "SELECT id, usuario, clave_hash FROM login WHERE usuario = ?",
      [nombre]
    );
    const hash = rows.length ? rows[0].clave_hash : HASH_RELLENO;
    const coincide = await bcrypt.compare(clave, hash);

    if (!rows.length || !coincide) {
      return res.status(401).json({ error: "Usuario o contraseña incorrectos" });
    }

    const token = jwt.sign(
      { id: rows[0].id, usuario: rows[0].usuario },
      JWT_SECRET,
      { expiresIn: "7d" }
    );
    res.json({ ok: true, id: rows[0].id, usuario: rows[0].usuario, token });
  } catch (err) {
    errorServidor(res, err, "Error al iniciar sesión");
  }
});

// ---------------------------- PRESTADORES DE SERVICIO ----------------------------

// Registro: crea el usuario (login), el sitio (sitios_cienaga) y los une (prestadores_servicio)
app.post("/registro-prestador", requireKey, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const { usuario, clave, nombre_sitio, descripcion, imagen_url, id_cat, direccion, categoria } = req.body || {};
    const nombre = typeof usuario === "string" ? usuario.trim() : "";
    const sitio = typeof nombre_sitio === "string" ? nombre_sitio.trim() : "";

    if (!nombre || !sitio || typeof clave !== "string" || !clave) {
      return res.status(400).json({ error: "Faltan datos obligatorios" });
    }
    if (nombre.length > 50) {
      return res.status(400).json({ error: "El usuario es demasiado largo (máximo 50)" });
    }
    if (clave.length < 6 || clave.length > 72) {
      return res.status(400).json({ error: "La contraseña debe tener entre 6 y 72 caracteres" });
    }
    if (id_cat != null && id_cat !== "" && !esEntero(id_cat)) {
      return res.status(400).json({ error: "Categoría no válida" });
    }

    let cat = id_cat ? Number(id_cat) : null;
    const nombreCat = typeof categoria === "string" ? categoria.trim().slice(0, 100) : "";
    const desc = typeof descripcion === "string" && descripcion.trim() ? descripcion.trim() : null;
    const img = typeof imagen_url === "string" && imagen_url.trim() ? imagen_url.trim() : null;
    const dir = typeof direccion === "string" && direccion.trim() ? direccion.trim() : null;
    const hash = await bcrypt.hash(clave, 10);

    await conn.beginTransaction();

    // Si llega la categoría escrita: se busca por nombre en "categorias"; si no existe, se crea
    if (!cat && nombreCat) {
      const [c] = await conn.query(
        "SELECT id_cat FROM categorias WHERE nombre = ?",
        [nombreCat]
      );
      if (c.length) {
        cat = c[0].id_cat;
      } else {
        const [nc] = await conn.query(
          "INSERT INTO categorias (nombre) VALUES (?)",
          [nombreCat]
        );
        cat = nc.insertId;
      }
    }

    const [u] = await conn.query(
      "INSERT INTO login (usuario, clave_hash) VALUES (?, ?)",
      [nombre, hash]
    );
    const [s] = await conn.query(
      `INSERT INTO sitios_cienaga (nombre, descripcion_historica, direccion, imagen_url, ${FK_CATEGORIA})
       VALUES (?, ?, ?, ?, ?)`,
      [sitio, desc, dir, img, cat]
    );
    await conn.query(
      `INSERT INTO prestadores_servicio
         (id_usuario, id_sitio, nombre_sitio, descripcion, direccion, imagen_url, id_cat)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [u.insertId, s.insertId, sitio, desc, dir, img, cat]
    );

    await conn.commit();
    res.status(201).json({ ok: true, mensaje: "Prestador registrado", id_sitio: s.insertId });
  } catch (err) {
    await conn.rollback();
    if (err.code === "ER_DUP_ENTRY") {
      return res.status(409).json({ error: "El usuario ya existe" });
    }
    if (err.code === "ER_NO_REFERENCED_ROW_2") {
      return res.status(400).json({ error: "La categoría no existe" });
    }
    errorServidor(res, err, "Error al registrar el prestador");
  } finally {
    conn.release();
  }
});

// ---------------------------- FAVORITOS (solo del usuario con sesión) ----------------------------

app.get("/mis-favoritos", requireKey, requireUser, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT s.id, s.nombre, s.descripcion_historica, c.nombre AS categoria, s.direccion, s.imagen_url
       FROM favoritos f
       JOIN sitios_cienaga s ON s.id = f.id_sitio
       LEFT JOIN categorias c ON c.id_cat = s.${FK_CATEGORIA}
       WHERE f.id_usuario = ?
       ORDER BY s.nombre`,
      [req.userId]
    );
    res.json(rows);
  } catch (err) {
    errorServidor(res, err, "Error al consultar tus favoritos");
  }
});

app.post("/favoritos", requireKey, requireUser, async (req, res) => {
  try {
    const idSitio = req.body?.id_sitio;
    if (!esEntero(idSitio)) {
      return res.status(400).json({ error: "id_sitio no válido" });
    }
    await pool.query(
      "INSERT INTO favoritos (id_usuario, id_sitio) VALUES (?, ?)",
      [req.userId, Number(idSitio)]
    );
    res.status(201).json({ ok: true });
  } catch (err) {
    if (err.code === "ER_DUP_ENTRY") return res.json({ ok: true }); // ya era favorito
    if (err.code === "ER_NO_REFERENCED_ROW_2") {
      return res.status(404).json({ error: "El sitio no existe" });
    }
    errorServidor(res, err, "Error al guardar el favorito");
  }
});

app.delete("/favoritos/:id_sitio", requireKey, requireUser, async (req, res) => {
  try {
    if (!esEntero(req.params.id_sitio)) {
      return res.status(400).json({ error: "id_sitio no válido" });
    }
    await pool.query(
      "DELETE FROM favoritos WHERE id_usuario = ? AND id_sitio = ?",
      [req.userId, Number(req.params.id_sitio)]
    );
    res.json({ ok: true });
  } catch (err) {
    errorServidor(res, err, "Error al quitar el favorito");
  }
});

// ---------------------------- COMENTARIOS (visibles para todos, con el nombre del autor) ----------------------------

app.get("/sitios/:id/comentarios", requireKey, async (req, res) => {
  try {
    if (!esEntero(req.params.id)) {
      return res.status(400).json({ error: "id no válido" });
    }
    const [rows] = await pool.query(
      `SELECT c.id, c.texto, c.creado_en, l.usuario
       FROM comentarios c
       JOIN login l ON l.id = c.id_usuario
       WHERE c.id_sitio = ?
       ORDER BY c.creado_en DESC`,
      [Number(req.params.id)]
    );
    res.json(rows);
  } catch (err) {
    errorServidor(res, err, "Error al consultar los comentarios");
  }
});

app.post("/sitios/:id/comentarios", requireKey, requireUser, async (req, res) => {
  try {
    if (!esEntero(req.params.id)) {
      return res.status(400).json({ error: "id no válido" });
    }
    const texto = typeof req.body?.texto === "string" ? req.body.texto.trim() : "";
    if (!texto) {
      return res.status(400).json({ error: "El comentario está vacío" });
    }
    await pool.query(
      "INSERT INTO comentarios (id_sitio, id_usuario, texto) VALUES (?, ?, ?)",
      [Number(req.params.id), req.userId, texto.slice(0, 500)]
    );
    res.status(201).json({ ok: true });
  } catch (err) {
    if (err.code === "ER_NO_REFERENCED_ROW_2") {
      return res.status(404).json({ error: "El sitio no existe" });
    }
    errorServidor(res, err, "Error al guardar el comentario");
  }
});

// Solo puedes borrar tus propios comentarios
app.delete("/comentarios/:id", requireKey, requireUser, async (req, res) => {
  try {
    if (!esEntero(req.params.id)) {
      return res.status(400).json({ error: "id no válido" });
    }
    const [r] = await pool.query(
      "DELETE FROM comentarios WHERE id = ? AND id_usuario = ?",
      [Number(req.params.id), req.userId]
    );
    if (r.affectedRows === 0) {
      return res.status(404).json({ error: "El comentario no existe o no es tuyo" });
    }
    res.json({ ok: true });
  } catch (err) {
    errorServidor(res, err, "Error al borrar el comentario");
  }
});

// ---------------------------- CATEGORÍAS ----------------------------

// Lista las categorías (tabla categorias). Se devuelve id_cat como "id" para no cambiar el contrato con la app.
app.get("/categorias", requireKey, async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT id_cat AS id, nombre FROM categorias ORDER BY nombre"
    );
    res.json(rows);
  } catch (err) {
    errorServidor(res, err, "Error al consultar las categorías");
  }
});

app.listen(PORT, () => console.log(`API escuchando en el puerto ${PORT}`));
