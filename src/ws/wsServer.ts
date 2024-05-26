import { Server } from 'http';
import { WebSocket } from 'ws';

interface Encuesta {
    id: string;
    pregunta: string;
    respuestas: string[];
}

let encuestas: Encuesta[] = [];

export function WebSocketServer(server: Server) {
    const wss = new WebSocket.Server({ server });

    wss.on('connection', (ws: WebSocket) => {
        console.log('Cliente conectado');

        ws.send(
            JSON.stringify({
                message: "Conectado al servidor de encuestas",
            })
        );

        ws.on('message', (data: string) => {
            console.log('Mensaje recibido: ', data.toString());
            const dataJson = JSON.parse(data);

            switch (dataJson.action) {
                case "getEncuestas":
                    ws.send(
                        JSON.stringify({
                            event: "getEncuestas",
                            data: encuestas,
                        })
                    );
                    break;

                case "crearEncuesta":
                    const idEncuesta = encuestas.length > 0 ? parseInt(encuestas[encuestas.length - 1].id) + 1 : 1;

                    const nuevaEncuesta: Encuesta = {
                        id: idEncuesta.toString(),
                        pregunta: dataJson.data.pregunta,
                        respuestas: dataJson.data.respuestas,
                    };

                    encuestas.push(nuevaEncuesta);

                    wss.clients.forEach((client) => {
                        if (client.readyState === WebSocket.OPEN) {
                            client.send(
                                JSON.stringify({
                                    event: "nuevaEncuesta",
                                    data: nuevaEncuesta,
                                })
                            );
                        }
                    });
                    break;
            }
        });

        ws.on('close', () => {
            console.log('Cliente desconectado');
        });

        ws.on('error', (error) => {
            console.error('Error en WebSocket:', error);
        });
    });

    console.log('WebSocket server is running');
}
