import express from "express";
import Razorpay from "razorpay";
import crypto from "crypto";
import cors from "cors";
import dotenv from "dotenv";
import admin from "firebase-admin";

dotenv.config();

const PORT = Number(process.env.PORT || 3000);
const ADMIN_EMAIL_ALLOWLIST = String(process.env.ADMIN_EMAIL_ALLOWLIST || "pharmazephyr@gmail.com")
  .split(",")
  .map((v) => v.trim().toLowerCase())
  .filter(Boolean);

function normalize(value) {
  return String(value || "").trim().toLowerCase();
}

function parseServiceAccount() {
  if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON_B64) {
    const raw = Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT_JSON_B64, "base64").toString("utf8");
    return JSON.parse(raw);
  }
  if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
    return JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
  }
  return null;
}

function initFirebaseAdmin() {
  if (admin.apps.length) return admin.app();
  const serviceAccount = parseServiceAccount();
  if (!serviceAccount) {
    console.warn("Firebase Admin not initialized: missing FIREBASE_SERVICE_ACCOUNT_JSON(_B64)");
    return null;
  }
  return admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
}

const firebaseApp = initFirebaseAdmin();
const adminDb = firebaseApp ? admin.firestore() : null;

const app = express();
app.use(cors());

app.post("/razorpay/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  try {
    const secret = process.env.RZP_WEBHOOK_SECRET;
    if (!secret) {
      return res.status(503).json({ error: "Webhook secret not configured" });
    }

    const signature = req.header("x-razorpay-signature");
    if (!signature) {
      return res.status(400).json({ error: "Missing webhook signature" });
    }

    const expected = crypto
      .createHmac("sha256", secret)
      .update(req.body)
      .digest("hex");

    if (expected !== signature) {
      return res.status(400).json({ error: "Invalid webhook signature" });
    }

    const payload = JSON.parse(req.body.toString("utf8"));
    await reconcileWebhookEvent(payload);
    return res.json({ ok: true });
  } catch (err) {
    console.error("Webhook error:", err);
    return res.status(500).json({ error: "Webhook processing failed" });
  }
});

app.use(express.json());

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    service: "pharmazephyr-razorpay",
    at: Date.now(),
    firebaseAdmin: !!adminDb,
  });
});

const razorpay = new Razorpay({
  key_id: process.env.RZP_KEY,
  key_secret: process.env.RZP_SECRET,
});

function sanitizeNotes(meta = {}) {
  const allowed = ["uid", "email", "fullName", "college", "phone", "description", "flow", "regId", "eventId", "eventRegistrationDocId"];
  const notes = {};
  for (const key of allowed) {
    if (!(key in meta)) continue;
    notes[key] = String(meta[key] ?? "").slice(0, 256);
  }
  return notes;
}

async function writeAdminAuditLog(action, details = {}) {
  if (!adminDb) return;
  try {
    await adminDb.collection("adminAuditLogs").add({
      action,
      details,
      source: details.source || "server",
      actorEmail: details.actorEmail || null,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
  } catch (err) {
    console.error("Audit log write failed:", err);
  }
}

async function reconcileEventPayment({ paymentId, orderId, source = "server", rawEvent = null }) {
  if (!adminDb) return { updated: 0, reason: "firebase_admin_unavailable" };
  if (!paymentId && !orderId) return { updated: 0, reason: "missing_payment_and_order" };

  let querySnap = null;
  if (paymentId) {
    querySnap = await adminDb.collection("eventRegistrations")
      .where("razorpayPaymentId", "==", paymentId)
      .limit(10)
      .get();
  }

  if ((!querySnap || querySnap.empty) && orderId) {
    querySnap = await adminDb.collection("eventRegistrations")
      .where("razorpayOrderId", "==", orderId)
      .limit(10)
      .get();
  }

  if (!querySnap || querySnap.empty) return { updated: 0, reason: "not_found" };

  const batch = adminDb.batch();
  let updated = 0;
  querySnap.docs.forEach((docSnap) => {
    const data = docSnap.data() || {};
    if (data.paymentStatus === "paid" && data.razorpayPaymentId) return;
    batch.update(docSnap.ref, {
      paymentStatus: "paid",
      razorpayPaymentId: paymentId || data.razorpayPaymentId || null,
      razorpayOrderId: orderId || data.razorpayOrderId || null,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    updated += 1;
  });
  if (updated > 0) await batch.commit();

  await writeAdminAuditLog("payment_reconciled", {
    source,
    paymentId: paymentId || null,
    orderId: orderId || null,
    matchedDocs: querySnap.docs.map((d) => d.id),
    rawEventType: rawEvent?.event || null,
  });

  return { updated };
}

async function reconcileWebhookEvent(payload) {
  const eventType = payload?.event;
  if (!eventType) return;

  const paymentEntity =
    payload?.payload?.payment?.entity ||
    payload?.payload?.order?.entity ||
    null;

  const paymentId = payload?.payload?.payment?.entity?.id || null;
  const orderId =
    payload?.payload?.payment?.entity?.order_id ||
    payload?.payload?.order?.entity?.id ||
    null;

  if (["payment.captured", "order.paid", "payment.authorized"].includes(eventType)) {
    await reconcileEventPayment({
      paymentId,
      orderId,
      source: "webhook",
      rawEvent: { event: eventType, entityId: paymentEntity?.id || null },
    });
  }
}

function requireFirebaseAdmin(req, res, next) {
  if (!adminDb) return res.status(503).json({ error: "Firebase Admin not configured" });
  next();
}

async function requireAdmin(req, res, next) {
  try {
    if (!adminDb) return res.status(503).json({ error: "Firebase Admin not configured" });
    const authHeader = String(req.headers.authorization || "");
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";
    if (!token) return res.status(401).json({ error: "Missing bearer token" });

    const decoded = await admin.auth().verifyIdToken(token);
    const email = normalize(decoded.email);
    if (!email || !ADMIN_EMAIL_ALLOWLIST.includes(email)) {
      return res.status(403).json({ error: "Forbidden" });
    }
    req.adminUser = decoded;
    next();
  } catch (err) {
    console.error("Admin auth failed:", err);
    res.status(401).json({ error: "Invalid admin token" });
  }
}

function mapDoc(docSnap) {
  return { id: docSnap.id, ...docSnap.data() };
}

app.post("/create-order", async (req, res) => {
  try {
    const requested = Number(req.body?.amount);
    const amount = Number.isFinite(requested) && requested > 0 ? Math.round(requested) : 19900;
    const receiptPrefix = String(req.body?.receiptPrefix || "pz26").replace(/[^a-zA-Z0-9_-]/g, "");
    const notes = sanitizeNotes(req.body?.meta || {});

    const order = await razorpay.orders.create({
      amount,
      currency: "INR",
      receipt: `${receiptPrefix}_${Date.now()}`,
      notes,
    });

    res.json(order);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Order creation failed" });
  }
});

app.post("/verify", async (req, res) => {
  const { order_id, payment_id, signature } = req.body || {};
  const body = `${order_id}|${payment_id}`;

  const expected = crypto
    .createHmac("sha256", process.env.RZP_SECRET)
    .update(body)
    .digest("hex");

  if (expected !== signature) {
    return res.status(400).json({ success: false });
  }

  try {
    const reconcile = await reconcileEventPayment({
      paymentId: payment_id || null,
      orderId: order_id || null,
      source: "verify_endpoint",
    });
    return res.json({ success: true, reconciled: reconcile });
  } catch (err) {
    console.error("Post-verify reconcile failed:", err);
    return res.json({ success: true, reconciled: { updated: 0, error: "reconcile_failed" } });
  }
});

app.get("/admin/summary", requireAdmin, requireFirebaseAdmin, async (_req, res) => {
  try {
    const [fest, events, paid, pending] = await Promise.all([
      adminDb.collection("registrations").count().get(),
      adminDb.collection("eventRegistrations").count().get(),
      adminDb.collection("eventRegistrations").where("paymentStatus", "==", "paid").count().get(),
      adminDb.collection("eventRegistrations").where("paymentStatus", "==", "pending").count().get(),
    ]);
    res.json({
      ok: true,
      stats: {
        festRegistrations: fest.data().count,
        eventRegistrations: events.data().count,
        paidEvents: paid.data().count,
        pendingPayments: pending.data().count,
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to load summary" });
  }
});

app.get("/admin/fest-registrations", requireAdmin, requireFirebaseAdmin, async (req, res) => {
  try {
    const limitN = Math.min(1000, Math.max(1, Number(req.query.limit || 500)));
    const snap = await adminDb.collection("registrations").orderBy("createdAt", "desc").limit(limitN).get();
    res.json({ ok: true, rows: snap.docs.map(mapDoc) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to load fest registrations" });
  }
});

app.get("/admin/event-registrations", requireAdmin, requireFirebaseAdmin, async (req, res) => {
  try {
    const limitN = Math.min(2000, Math.max(1, Number(req.query.limit || 1000)));
    const snap = await adminDb.collection("eventRegistrations").orderBy("createdAt", "desc").limit(limitN).get();
    res.json({ ok: true, rows: snap.docs.map(mapDoc) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to load event registrations" });
  }
});

app.post("/admin/fest-checkin", requireAdmin, requireFirebaseAdmin, async (req, res) => {
  try {
    const regId = String(req.body?.regId || "").trim();
    const checkedIn = !!req.body?.checkedIn;
    if (!regId) return res.status(400).json({ error: "regId is required" });

    await adminDb.collection("registrations").doc(regId).update({
      checkedIn,
      checkedInAt: checkedIn ? admin.firestore.FieldValue.serverTimestamp() : null,
      checkedInBy: checkedIn ? normalize(req.adminUser.email || "admin") : null,
    });

    await writeAdminAuditLog("fest_checkin_update", {
      source: "admin_api",
      actorEmail: normalize(req.adminUser.email || ""),
      regId,
      checkedIn,
    });

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to update fest check-in" });
  }
});

app.post("/admin/event-payment-status", requireAdmin, requireFirebaseAdmin, async (req, res) => {
  try {
    const docId = String(req.body?.docId || "").trim();
    const paymentStatus = String(req.body?.paymentStatus || "").trim();
    if (!docId) return res.status(400).json({ error: "docId is required" });
    if (!["paid", "pending", "not_required", "failed"].includes(paymentStatus)) {
      return res.status(400).json({ error: "Invalid paymentStatus" });
    }

    await adminDb.collection("eventRegistrations").doc(docId).update({
      paymentStatus,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    await writeAdminAuditLog("event_payment_status_update", {
      source: "admin_api",
      actorEmail: normalize(req.adminUser.email || ""),
      docId,
      paymentStatus,
    });

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to update event payment status" });
  }
});

app.get("/admin/audit-logs", requireAdmin, requireFirebaseAdmin, async (req, res) => {
  try {
    const limitN = Math.min(200, Math.max(1, Number(req.query.limit || 100)));
    const snap = await adminDb.collection("adminAuditLogs").orderBy("createdAt", "desc").limit(limitN).get();
    res.json({ ok: true, rows: snap.docs.map(mapDoc) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to load audit logs" });
  }
});

app.listen(PORT, () => {
  console.log(`Razorpay server running on ${PORT}`);
});
