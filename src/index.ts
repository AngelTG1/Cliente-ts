import express, { NextFunction, Request, Response } from "express";
import cors from "cors";
import { createServer } from "http";
import { WebSocket, WebSocketServer as WSServer } from "ws";
import { Sequelize, DataTypes, Model } from "sequelize";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import dotenv from "dotenv";
import axios from 'axios';

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;
const secretKey = process.env.SECRET_KEY || "default_secret_key";

app.use(express.json());
app.use(cors());

const sequelize = new Sequelize(
  process.env.DB_NAME || 'encuestasdb',
  process.env.DB_USER || 'username',
  process.env.DB_PASSWORD || 'password',
  {
    host: process.env.DB_HOST || 'localhost',
    dialect: process.env.DB_DIALECT as any || 'mysql',
  }
);

class Url extends Model {
  public id!: number;
  public url!: string;
}

Url.init({
  id: {
    type: DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true
  },
  url: {
    type: DataTypes.STRING,
    allowNull: false,
  }
}, {
  sequelize,
  modelName: 'url'
});

class Usuario extends Model {
  public id!: number;
  public name!: string;
  public password!: string;
}

Usuario.init({
  id: {
    type: DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true
  },
  name: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false
  }
}, {
  sequelize,
  modelName: 'usuario'
});

class Encuesta extends Model {
  public id!: number;
  public pregunta!: string;
  public respuestas!: string[];
  public status!: number;
}

Encuesta.init({
  id: {
    type: DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true
  },
  pregunta: {
    type: DataTypes.STRING,
    allowNull: false
  },
  respuestas: {
    type: DataTypes.JSON,
    allowNull: false
  },
  status: {
    type: DataTypes.INTEGER,
    allowNull: false
  }
}, {
  sequelize,
  modelName: 'encuesta'
});

class Voto extends Model {
  public id!: number;
  public encuestaId!: number;
  public respuesta!: string;
}

Voto.init({
  id: {
    type: DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true
  },
  encuestaId: {
    type: DataTypes.INTEGER,
    allowNull: false
  },
  respuesta: {
    type: DataTypes.STRING,
    allowNull: false
  }
}, {
  sequelize,
  modelName: 'voto'
});

sequelize.sync().then(() => {
  console.log("Conectado a MySQL");
}).catch(error => {
  console.error("Error conectando a MySQL:", error);
});

const sendNotification = async (message: string) => {
  try {
    const webhookUrlRecord = await Url.findOne();
    if (!webhookUrlRecord) {
      console.error('No se ha registrado una URL de webhook.');
      return;
    }

    const webhookUrl = webhookUrlRecord.url;

    const response = await axios.post(webhookUrl, {
      content: message
    });

    console.log('Mensaje enviado a Discord', response.data);
  } catch (error) {
    if (axios.isAxiosError(error)) {
      console.error('Error enviando mensaje a Discord:', error.message, error.response?.data);
    } else {
      console.error('Error enviando mensaje a Discord:', error);
    }
  }
};



const authenticateJWT = (req: Request, res: Response, next: NextFunction) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (token) {
    jwt.verify(token, secretKey, (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }
      (req as any).user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
};

app.post("/register", async (req: Request, res: Response) => {
  const { name, password } = req.body;
  const existingUser = await Usuario.findOne({ where: { name } });

  if (existingUser) {
    return res.status(400).json({ success: false, message: "User already exists" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = await Usuario.create({ name, password: hashedPassword });

  res.json({ success: true, message: "User registered successfully" });
});

app.post("/login", async (req: Request, res: Response) => {
  const { name, password } = req.body;

  try {
    const user = await Usuario.findOne({ where: { name } });

    if (!user) {
      return res.status(400).json({ success: false, message: "Invalid credentials" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(400).json({ success: false, message: "Invalid credentials" });
    }

    const token = jwt.sign({ id: user.id, name: user.name }, secretKey, { expiresIn: "1h" });

    res.json({ success: true, token });
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

let responses: Response[] = [];
const clients: { res: Response }[] = [];

// Función para enviar eventos SSE a los clientes conectados
function sendSSEEvent(event: string, data: any) {
  const eventData = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  clients.forEach((client) => {
    client.res.write(eventData);
  });
}

app.get("/events", (req: Request, res: Response) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");

  clients.push({ res });

  req.on("close", () => {
    const index = clients.findIndex(client => client.res === res);
    if (index !== -1) {
      clients.splice(index, 1);
    }
    res.end();
  });
});

app.get("/encuesta-nueva", (req: Request, res: Response) => {
  responses.push(res);
});

app.post("/crear-encuesta", async (req: Request, res: Response) => {
  const { pregunta, respuestas } = req.body;

  if (!pregunta || !respuestas) {
    return res.status(400).json({ success: false, message: "Pregunta y respuestas son requeridas" });
  }

  try {
    const nuevaEncuesta = await Encuesta.create({ pregunta, respuestas, status: 1 });

    // Notificación a Discord para nueva encuesta
    await sendNotification(`Nueva encuesta creada: ${pregunta}`);

    // Enviar la nueva encuesta a los clientes conectados vía SSE
    sendSSEEvent("nuevaEncuesta", nuevaEncuesta);

    res.status(201).json({
      success: true,
      encuesta: nuevaEncuesta
    });
  } catch (error) {
    console.error("Error creando encuesta:", error);
    res.status(500).json({ success: false, message: "Error interno del servidor" });
  }
});

app.post("/enviar-respuesta/:id", authenticateJWT, async (req: Request, res: Response) => {
  const encuestaId = req.params.id;
  const respuesta = req.body.respuesta;

  try {
    const encuesta = await Encuesta.findByPk(encuestaId);

    if (!encuesta) {
      return res.status(404).json({ success: false, message: "Encuesta no encontrada" });
    }

    if (encuesta.status === 0) {
      return res.status(400).json({ success: false, message: "No se puede responder a una encuesta cerrada" });
    }

    await Voto.create({ encuestaId: Number(encuestaId), respuesta });

    // Obtén los votos actualizados
    const votos = await Voto.findAll({ where: { encuestaId: Number(encuestaId) } });
    const conteoVotos = votos.reduce((acc: { [key: string]: number }, voto) => {
      acc[voto.respuesta] = (acc[voto.respuesta] || 0) + 1;
      return acc;
    }, {});

    // Notificación a Discord para nuevo voto
    await sendNotification(`Nuevo voto en la encuesta ${encuestaId}: ${respuesta}`);

    // Envía la actualización a todos los clientes conectados vía SSE
    sendSSEEvent("actualizacionVotos", { encuestaId, conteoVotos });

    res.json({
      success: true,
      message: "Respuesta enviada",
    });
  } catch (error) {
    console.error("Error enviando respuesta:", error);
    res.status(500).json({ success: false, message: "Error interno del servidor" });
  }
});

app.get("/ver-encuestas", authenticateJWT, async (req: Request, res: Response) => {
  const encuestas = await Encuesta.findAll();
  res.json({ success: true, encuestas });
});

app.get('/encuestas-estado', authenticateJWT, async (req: Request, res: Response) => {
  const { estado } = req.query;

  if (estado === undefined) {
    return res.status(400).json({ success: false, message: "Estado es requerido" });
  }

  try {
    const encuestas = await Encuesta.findAll({
      where: {
        status: estado
      }
    });

    const encuestasIds = encuestas.map(encuesta => encuesta.id);
    console.log(`Encuestas ${estado === '0' ? 'cerradas' : 'abiertas'}:`, encuestasIds);

    res.json({ success: true, encuestas });
  } catch (error) {
    console.error("Error recuperando encuestas:", error);
    res.status(500).json({ success: false, message: "Error interno del servidor" });
  }
});

function responderClientes(encuesta: Encuesta) {
  for (let res of responses) {
    res.json({ success: true, encuesta });
  }
  responses = [];
}

function responderVotos(encuestaId: number, conteoVotos: { [key: string]: number }) {
  const data = JSON.stringify({ event: "actualizacionVotos", data: { encuestaId, conteoVotos } });

  for (let res of responses) {
    res.send(data);
  }
  responses = [];
}

app.post("/encuesta-status", authenticateJWT, async (req: Request, res: Response) => {
  const { id, status } = req.body;

  if (id === undefined || status === undefined) {
    return res.status(400).json({ success: false, message: "ID and status are required" });
  }

  try {
    const encuesta = await Encuesta.findByPk(id);

    if (!encuesta) {
      return res.status(404).json({ success: false, message: "Encuesta not found" });
    }

    encuesta.status = status;
    await encuesta.save();

    await sendNotification(`Status actualizado: ${status}`);

    // Enviar el estado actualizado a los clientes conectados vía SSE
    sendSSEEvent("actualizacionEstadoEncuesta", { id: encuesta.id, status });

    res.json({ success: true, message: "Encuesta status updated successfully" });
  } catch (error) {
    console.error("Error updating encuesta status:", error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});


app.post('/register-url', async (req: Request, res: Response) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ success: false, message: "URL es requerida" });
  }

  try {
    const existingUrl = await Url.findOne();
    if (existingUrl) {
      existingUrl.url = url;
      await existingUrl.save();
    } else {
      await Url.create({ url });
    }

    res.status(201).json({ success: true, message: "URL registrada correctamente" });
  } catch (error) {
    console.error("Error registrando URL:", error);
    res.status(500).json({ success: false, message: "Error interno del servidor" });
  }
});

const server = createServer(app);

const wss = new WSServer({ server });

wss.on("connection", (ws: WebSocket) => {
  console.log("Cliente conectado");

  ws.on("message", async (data: string) => {
    console.log("Mensaje recibido: ", data.toString());
    const dataJson = JSON.parse(data);

    switch (dataJson.action) {
      case "getEncuestas":
        const encuestas = await Encuesta.findAll();
        ws.send(JSON.stringify({ event: "getEncuestas", data: encuestas }));
        break;

      case "crearEncuesta":
        const nuevaEncuesta = await Encuesta.create({
          pregunta: dataJson.data.pregunta,
          respuestas: dataJson.data.respuestas,
          status: 1
        });

        // Notificación a Discord para nueva encuesta
        await sendNotification(`Nueva encuesta creada: ${dataJson.data.pregunta}`);

        // Enviar evento SSE a los clientes conectados
        sendSSEEvent("nuevaEncuesta", nuevaEncuesta);
        break;

      case "votar":
        const { encuestaId, respuesta } = dataJson.data;

        // Guarda el voto en la base de datos
        await Voto.create({ encuestaId, respuesta });

        // Obtén los votos actualizados
        const votos = await Voto.findAll({ where: { encuestaId } });
        const conteoVotos = votos.reduce((acc: { [key: string]: number }, voto) => {
          acc[voto.respuesta] = (acc[voto.respuesta] || 0) + 1;
          return acc;
        }, {});

        // Notificación a Discord para nuevo voto
        await sendNotification(`Nuevo voto en la encuesta ${encuestaId}: ${respuesta}`);

        // Envía la actualización a todos los clientes conectados vía SSE
        sendSSEEvent("actualizacionVotos", { encuestaId, conteoVotos });
        break;
    }
  });

  ws.on("close", () => {
    console.log("Cliente desconectado");
  });

  ws.on("error", (error) => {
    console.error("Error en WebSocket:", error);
  });
});

server.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
