import express from "express";
import dotenv from "dotenv";
import { exec } from "child_process";
import crypto from "crypto";

dotenv.config();

const app = express();
const port = 3000;
const BUILD_DIR = "/var/www/goremote.pro/";

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

function verifySignature(req, res, next) {
  const payload = JSON.stringify(req.body);
  if (!payload) return next("Request body empty");

  const sigHeaderName = "x-hub-signature-256";
  const signature = req.headers[sigHeaderName];
  if (!signature) {
    return res.status(403).send("No signature found!");
  }

  const hmac = crypto.createHmac("sha256", process.env.SECRET);
  const digest = "sha256=" + hmac.update(payload).digest("hex");

  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(digest))) {
    return res.status(403).send("Invalid signature");
  }

  next();
}

app.post("/webhook", verifySignature, (req, res) => {
  console.log("GitHub Webhook Received");

  if (
    req.headers["x-github-event"] === "push" &&
    req.body.ref === "refs/heads/main"
  ) {
    exec(`cd ${BUILD_DIR} && git pull`, (error, stdout, stderr) => {
      if (error) {
        console.error(`exec error: ${error}`);
        return res.status(500).send("Error executing git pull");
      }
      console.log(`stdout: ${stdout}`);
      console.error(`stderr: ${stderr}`);
      res.status(200).send("Webhook received and git pull executed");
    });
  } else {
    res.status(200).send("Webhook received, no action taken");
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
