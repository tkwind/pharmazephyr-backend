import express from "express";
import Razorpay from "razorpay";
import crypto from "crypto";
import cors from "cors";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const razorpay = new Razorpay({
  key_id: process.env.RZP_KEY,
  key_secret: process.env.RZP_SECRET
});

/* Create order */
app.post("/create-order", async (req, res) => {
  try {
    const amount = 19900; // ₹199 locked server-side (safe)

    const order = await razorpay.orders.create({
      amount,
      currency: "INR",
      receipt: "pz26_" + Date.now()
    });

    res.json(order);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Order creation failed" });
  }
});

/* Verify payment */
app.post("/verify", (req, res) => {
  const { order_id, payment_id, signature } = req.body;

  const body = order_id + "|" + payment_id;

  const expected = crypto
    .createHmac("sha256", process.env.RZP_SECRET)
    .update(body)
    .digest("hex");

  if (expected === signature) {
    res.json({ success: true });
  } else {
    res.status(400).json({ success: false });
  }
});

app.listen(3000, () => console.log("Razorpay server running on 3000"));
