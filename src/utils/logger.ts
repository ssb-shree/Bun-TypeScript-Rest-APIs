import pino from "pino";
import pretty from "pino-pretty";

// config for the console
const consoleStream = pretty({
  colorize: true,
  translateTime: "HH:MM:ss",
  ignore: "pid,hostname",
});

// config to save logs in a file
const fileStream = pino.destination("logs/app.log");

const logger = pino(
  { level: "info" },
  // usinf multistream to get logs in both console and file
  pino.multistream([
    { stream: consoleStream }, // console logs
    { stream: fileStream }, // file logs
  ])
);

export default logger;
