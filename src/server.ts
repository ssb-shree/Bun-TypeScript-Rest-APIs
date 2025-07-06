import config from "config";

import app from "./app";
import connectDB from "./utils/db";
import logger from "./utils/logger";

const port = config.get<number>("port");

const startServer = async () => {
  const db = await connectDB();

  if (db) {
    app.listen(port, () => logger.info(`Server is running at ${port}, DB connected to host ${db.connection.host}`));
  } else {
    logger.fatal("Shutting down the server");
    process.exit(1);
  }
};

startServer();
