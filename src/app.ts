import express from "express";

import morgan from "morgan"; // http logger

const app = express();

app.use(
  morgan(
    "\x1b[36m:date[web]\x1b[0m \x1b[33m:method\x1b[0m At(\x1b[34m:url\x1b[0m) Status[\x1b[32m:status\x1b[0m] - [\x1b[35m:response-time ms\x1b[0m]"
  )
);

export default app;
