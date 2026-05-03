import app from "./app.js";
import { checkDbConnection } from "./db/db.js";
import { env } from "./env.js";
import dotenv from "dotenv";
dotenv.config();
app.listen(env.PORT, async () => {
  console.log(`Cortex Auth running on PORT:${env.PORT}`);

  try {
    await checkDbConnection();
    console.log("PostgreSQL connected successfully");
  } catch (err) {
    console.error("PostgreSQL connection failed:", err);
    process.exit(1);
  }
});
