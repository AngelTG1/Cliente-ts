import express, { NextFunction, Request, Response } from "express";
import cors from "cors";
import { createServer } from "http";
import { WebSocket } from "ws";
import { Server } from "http";
import { Sequelize, DataTypes, Model } from "sequelize";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import dotenv from "dotenv";

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
  }
}, {
  sequelize,
  modelName: 'encuesta'
});

sequelize.sync().then(() => {
  console.log("Connected to MySQL");
}).catch(error => {
  console.error("Error connecting to MySQL:", error);
});

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

app.get("/encuesta-nueva", authenticateJWT, (req: Request, res: Response) => {
  responses.push(res);
});

app.post("/crear-encuesta", authenticateJWT, async (req: Request, res: Response) => {
  const { pregunta, respuestas } = req.body;
  const nuevaEncuesta = await Encuesta.create({ pregunta, respuestas });

  responderClientes(nuevaEncuesta);

  res.json({ success: true, encuesta: nuevaEncuesta });
});

app.post("/enviar-respuesta/:id", authenticateJWT, (req: Request, res: Response) => {
  const encuestaId = req.params.id;
  const respuesta = req.body.respuesta;

  console.log(`Encuesta ID: ${encuestaId}, Respuesta: ${respuesta}`);

  res.json({
    success: true,
    message: "Respuesta recibida",
  });
});

app.get("/ver-encuestas", authenticateJWT, async (req: Request, res: Response) => {
  const encuestas = await Encuesta.findAll();
  res.json({ success: true, encuestas });
});

function responderClientes(encuesta: Encuesta) {
  for (let res of responses) {
    res.json({ success: true, encuesta });
  }
  responses = [];
}

export function WebSocketServer(server: Server) {
  const wss = new WebSocket.Server({ server });

  wss.on("connection", (ws: WebSocket) => {
    console.log("Cliente conectado");

    ws.send(JSON.stringify({ message: "Conectado al servidor de encuestas" }));

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
          });

          wss.clients.forEach((client) => {
            if (client.readyState === WebSocket.OPEN) {
              client.send(JSON.stringify({ event: "nuevaEncuesta", data: nuevaEncuesta }));
            }
          });
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

  console.log("WebSocket server is running");
}

const server = createServer(app);
WebSocketServer(server);

server.listen(port, () => {
  console.log(`Server running on ${port}`);
});
