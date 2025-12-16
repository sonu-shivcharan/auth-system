import { configDotenv } from "dotenv";
import app from "./app.js";
configDotenv();

const port = process.env.PORT || 3000;

app.listen(port, () => {
  console.log(`Example app listening on port http://localhost:${port}`);
});
