import app from "./app.js";
import { env } from "./env.js";
import dotenv from "dotenv";
dotenv.config();
app.listen(env.PORT, () => {
  console.log(`Cortex Auth running on http://localhost:${env.PORT}`);
  console.log(`http://localhost:${env.PORT}/.well-known/openid-configuration`);
});
