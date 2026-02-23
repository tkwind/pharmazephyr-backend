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

function makeEventRegistrationDocId(regId, eventId) {
  const safeRegId = String(regId || "reg").replace(/[^a-zA-Z0-9_-]/g, "_");
  const safeEventId = String(eventId || "event").replace(/[^a-zA-Z0-9_-]/g, "_");
  return `${safeRegId}__${safeEventId}`;
}

function parseAmount(value) {
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? n : 0;
}

function verifyRazorpaySignature(orderId, paymentId, signature) {
  const body = `${orderId}|${paymentId}`;
  const expected = crypto
    .createHmac("sha256", process.env.RZP_SECRET)
    .update(body)
    .digest("hex");
  return expected === signature;
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
    const webhookEventId = String(req.header("x-razorpay-event-id") || "").trim();
    const dedupeKey = webhookEventId || crypto.createHash("sha256").update(req.body).digest("hex");
    const accepted = await markWebhookEventProcessed(dedupeKey, payload);
    if (!accepted) {
      return res.json({ ok: true, duplicate: true });
    }
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

async function markWebhookEventProcessed(eventKey, payload = {}) {
  if (!adminDb) return true;
  if (!eventKey) return true;
  const ref = adminDb.collection("processedWebhookEvents").doc(String(eventKey));
  try {
    await adminDb.runTransaction(async (tx) => {
      const snap = await tx.get(ref);
      if (snap.exists) {
        throw new Error("duplicate_webhook_event");
      }
      tx.set(ref, {
        eventKey: String(eventKey),
        razorpayEventType: payload?.event || null,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    });
    return true;
  } catch (err) {
    if (String(err?.message || "").includes("duplicate_webhook_event")) return false;
    throw err;
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

async function finalizeEventRegistrationServer({
  user,
  regId,
  eventId,
  category,
  eventName,
  eventDesc = "",
  eventPrice = "—",
  amount = 0,
  paymentRequired = false,
  paymentStatus = "not_required",
  razorpayOrderId = null,
  razorpayPaymentId = null,
}) {
  if (!adminDb) throw new Error("Firebase Admin not configured");

  const eventAmount = parseAmount(amount);
  const docId = makeEventRegistrationDocId(regId, eventId);
  const regRef = adminDb.collection("registrations").doc(regId);
  const eventRegistryRef = adminDb.collection("eventsRegistry").doc(eventId);
  const participantRef = eventRegistryRef.collection("participants").doc(regId);
  const eventRegistrationRef = adminDb.collection("eventRegistrations").doc(docId);
  let emailContext = null;

  let didAdd = false;
  await adminDb.runTransaction(async (tx) => {
    const regSnap = await tx.get(regRef);
    if (!regSnap.exists) throw new Error("Registration not found");

    const reg = regSnap.data() || {};
    if (reg.uid && reg.uid !== user.uid) throw new Error("Registration owner mismatch");
    if (!reg.uid && normalize(reg.email) !== normalize(user.email || "")) {
      throw new Error("Registration owner mismatch");
    }

    const current = Array.isArray(reg.registeredEvents) ? reg.registeredEvents : [];
    if (current.some((x) => x?.id === eventId)) return;

    didAdd = true;
    const next = [
      ...current,
      {
        id: eventId,
        category,
        name: eventName,
        desc: eventDesc,
        price: eventPrice,
        registeredAt: admin.firestore.Timestamp.now(),
      },
    ];

    tx.update(regRef, { registeredEvents: next });

    tx.set(eventRegistryRef, {
      eventId,
      category,
      name: eventName,
      desc: eventDesc,
      priceLabel: eventPrice,
      amount: eventAmount,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    }, { merge: true });

    tx.set(participantRef, {
      regId,
      uid: reg.uid || user.uid,
      email: reg.email || normalize(user.email || ""),
      fullName: reg.fullName || user.name || "",
      college: reg.college || "",
      phone: reg.phone || "",
      eventId,
      category,
      eventName,
      eventPrice,
      amount: eventAmount,
      status: "registered",
      source: "server",
      registeredAt: admin.firestore.FieldValue.serverTimestamp(),
    }, { merge: true });

    tx.set(eventRegistrationRef, {
      registrationDocId: docId,
      regId,
      uid: reg.uid || user.uid,
      email: reg.email || normalize(user.email || ""),
      fullName: reg.fullName || user.name || "",
      college: reg.college || "",
      phone: reg.phone || "",
      eventId,
      category,
      eventName,
      eventDesc,
      eventPrice,
      amount: eventAmount,
      paymentRequired: !!paymentRequired,
      paymentStatus,
      status: "registered",
      source: "server",
      razorpayOrderId: razorpayOrderId || null,
      razorpayPaymentId: razorpayPaymentId || null,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    }, { merge: true });

    emailContext = {
      reg: {
        regId,
        fullName: reg.fullName || user.name || "",
        email: reg.email || normalize(user.email || ""),
        college: reg.college || "",
      },
      event: {
        regId,
        eventId,
        eventName,
        category,
        eventPrice,
      },
    };
  });

  await writeAdminAuditLog("event_registration_finalize", {
    source: "event_finalize_api",
    actorEmail: normalize(user.email || ""),
    regId,
    eventId,
    paymentStatus,
    added: didAdd,
  });

  return { added: didAdd, docId, emailContext };
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

async function requireUser(req, res, next) {
  try {
    if (!adminDb) return res.status(503).json({ error: "Firebase Admin not configured" });
    const authHeader = String(req.headers.authorization || "");
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";
    if (!token) return res.status(401).json({ error: "Missing bearer token" });
    const decoded = await admin.auth().verifyIdToken(token);
    req.userToken = decoded;
    next();
  } catch (err) {
    console.error("User auth failed:", err);
    res.status(401).json({ error: "Invalid user token" });
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
  if (!verifyRazorpaySignature(order_id, payment_id, signature)) {
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

app.post("/event/finalize-registration", requireUser, requireFirebaseAdmin, async (req, res) => {
  try {
    const {
      regId,
      eventId,
      category,
      eventName,
      eventDesc = "",
      eventPrice = "—",
      amount = 0,
      orderId = null,
      paymentId = null,
      signature = null,
    } = req.body || {};

    if (!regId || !eventId || !category || !eventName) {
      return res.status(400).json({ error: "Missing required event registration fields" });
    }

    const numericAmount = parseAmount(amount);
    const paymentRequired = numericAmount > 0;
    let paymentStatus = paymentRequired ? "pending" : "not_required";

    if (paymentRequired) {
      if (!orderId || !paymentId || !signature) {
        return res.status(400).json({ error: "Missing payment proof for paid event" });
      }
      if (!verifyRazorpaySignature(orderId, paymentId, signature)) {
        return res.status(400).json({ error: "Invalid Razorpay signature" });
      }
      paymentStatus = "paid";
    }

    const result = await finalizeEventRegistrationServer({
      user: {
        uid: req.userToken.uid,
        email: req.userToken.email || null,
        name: req.userToken.name || null,
      },
      regId: String(regId),
      eventId: String(eventId),
      category: String(category),
      eventName: String(eventName),
      eventDesc: String(eventDesc || ""),
      eventPrice: String(eventPrice || "—"),
      amount: numericAmount,
      paymentRequired,
      paymentStatus,
      razorpayOrderId: orderId || null,
      razorpayPaymentId: paymentId || null,
    });

    res.json({ ok: true, added: !!result?.added, docId: result?.docId, paymentStatus });
  } catch (err) {
    console.error("Event finalize failed:", err);
    res.status(500).json({ error: err?.message || "Event finalization failed" });
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

app.get("/admin/events", requireAdmin, requireFirebaseAdmin, async (_req, res) => {
  try {
    const [cfgSnap, registrySnap] = await Promise.all([
      adminDb.collection("events").get(),
      adminDb.collection("eventsRegistry").get(),
    ]);

    const merged = new Map();

    cfgSnap.docs.forEach((docSnap) => {
      const row = mapDoc(docSnap);
      const eventId = String(row.eventId || row.id || "").trim();
      if (!eventId) return;
      merged.set(eventId, {
        ...row,
        eventId,
        _source: "events",
      });
    });

    registrySnap.docs.forEach((docSnap) => {
      const row = mapDoc(docSnap);
      const eventId = String(row.eventId || row.id || "").trim();
      if (!eventId) return;
      const existing = merged.get(eventId) || {};
      merged.set(eventId, {
        eventId,
        category: existing.category ?? row.category ?? "",
        categoryTitle: existing.categoryTitle ?? row.categoryTitle ?? "",
        name: existing.name ?? row.name ?? "",
        desc: existing.desc ?? row.desc ?? "",
        priceLabel: existing.priceLabel ?? row.priceLabel ?? "—",
        amount: existing.amount ?? row.amount ?? 0,
        pricingMode: existing.pricingMode ?? "single",
        internalPriceLabel: existing.internalPriceLabel ?? "",
        internalAmount: existing.internalAmount ?? null,
        externalPriceLabel: existing.externalPriceLabel ?? "",
        externalAmount: existing.externalAmount ?? null,
        participationMode: existing.participationMode ?? "",
        participationLabel: existing.participationLabel ?? "",
        active: existing.active ?? true,
        capacity: existing.capacity ?? null,
        teamSize: existing.teamSize ?? null,
        sortOrder: existing.sortOrder ?? 0,
        updatedAt: existing.updatedAt ?? row.updatedAt ?? null,
        updatedBy: existing.updatedBy ?? null,
        _source: existing._source ? "events+registry" : "eventsRegistry",
        ...existing,
      });
    });

    const rows = Array.from(merged.values()).sort((a, b) => {
      const ac = String(a.category || "");
      const bc = String(b.category || "");
      if (ac !== bc) return ac.localeCompare(bc);
      return String(a.name || "").localeCompare(String(b.name || ""));
    });
    res.json({ ok: true, rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to load events config" });
  }
});

app.post("/admin/events/upsert", requireAdmin, requireFirebaseAdmin, async (req, res) => {
  try {
    const {
      eventId,
      category,
      categoryTitle = "",
      name,
      desc = "",
      priceLabel = "—",
      amount = 0,
      pricingMode = "single",
      internalPriceLabel = "",
      internalAmount = null,
      externalPriceLabel = "",
      externalAmount = null,
      participationMode = "",
      participationLabel = "",
      active = true,
      capacity = null,
      teamSize = null,
      sortOrder = 0,
    } = req.body || {};

    if (!eventId || !category || !name) {
      return res.status(400).json({ error: "eventId, category, and name are required" });
    }

    const payload = {
      eventId: String(eventId),
      category: String(category),
      categoryTitle: String(categoryTitle || ""),
      name: String(name),
      desc: String(desc || ""),
      priceLabel: String(priceLabel || "—"),
      amount: parseAmount(amount),
      pricingMode: String(pricingMode || "single"),
      internalPriceLabel: String(internalPriceLabel || ""),
      internalAmount: internalAmount == null || internalAmount === "" ? null : parseAmount(internalAmount),
      externalPriceLabel: String(externalPriceLabel || ""),
      externalAmount: externalAmount == null || externalAmount === "" ? null : parseAmount(externalAmount),
      participationMode: String(participationMode || ""),
      participationLabel: String(participationLabel || ""),
      active: !!active,
      capacity: capacity == null || capacity === "" ? null : Number(capacity),
      teamSize: teamSize == null || teamSize === "" ? null : Number(teamSize),
      sortOrder: Number.isFinite(Number(sortOrder)) ? Number(sortOrder) : 0,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedBy: normalize(req.adminUser.email || ""),
    };

    await adminDb.collection("events").doc(String(eventId)).set(payload, { merge: true });

    await writeAdminAuditLog("event_config_upsert", {
      source: "admin_api",
      actorEmail: normalize(req.adminUser.email || ""),
      eventId: String(eventId),
      category: String(category),
      categoryTitle: String(categoryTitle || ""),
      active: !!active,
      amount: parseAmount(amount),
    });

    res.json({ ok: true, event: payload });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to save event config" });
  }
});

app.post("/admin/events/bulk-upsert", requireAdmin, requireFirebaseAdmin, async (req, res) => {
  try {
    const rows = Array.isArray(req.body?.events) ? req.body.events : [];
    if (!rows.length) return res.status(400).json({ error: "events array is required" });

    const batch = adminDb.batch();
    let saved = 0;

    for (const row of rows) {
      const eventId = String(row?.eventId || "").trim();
      const category = String(row?.category || "").trim();
      const name = String(row?.name || "").trim();
      if (!eventId || !category || !name) continue;

      const payload = {
        eventId,
        category,
        categoryTitle: String(row?.categoryTitle || ""),
        name,
        desc: String(row?.desc || ""),
        priceLabel: String(row?.priceLabel || "—"),
        amount: parseAmount(row?.amount),
        pricingMode: String(row?.pricingMode || "single"),
        internalPriceLabel: String(row?.internalPriceLabel || ""),
        internalAmount: row?.internalAmount == null || row?.internalAmount === "" ? null : parseAmount(row.internalAmount),
        externalPriceLabel: String(row?.externalPriceLabel || ""),
        externalAmount: row?.externalAmount == null || row?.externalAmount === "" ? null : parseAmount(row.externalAmount),
        participationMode: String(row?.participationMode || ""),
        participationLabel: String(row?.participationLabel || ""),
        active: row?.active !== false,
        capacity: row?.capacity == null || row?.capacity === "" ? null : Number(row.capacity),
        teamSize: row?.teamSize == null || row?.teamSize === "" ? null : Number(row.teamSize),
        sortOrder: Number.isFinite(Number(row?.sortOrder)) ? Number(row.sortOrder) : 0,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedBy: normalize(req.adminUser.email || ""),
      };

      batch.set(adminDb.collection("events").doc(eventId), payload, { merge: true });
      saved += 1;
    }

    if (!saved) return res.status(400).json({ error: "No valid events to import" });

    await batch.commit();

    await writeAdminAuditLog("event_config_bulk_upsert", {
      source: "admin_api",
      actorEmail: normalize(req.adminUser.email || ""),
      count: saved,
    });

    res.json({ ok: true, count: saved });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to bulk import events" });
  }
});

app.post("/admin/events/delete", requireAdmin, requireFirebaseAdmin, async (req, res) => {
  try {
    const eventId = String(req.body?.eventId || "").trim();
    if (!eventId) return res.status(400).json({ error: "eventId is required" });

    await adminDb.collection("events").doc(eventId).delete();

    await writeAdminAuditLog("event_config_delete", {
      source: "admin_api",
      actorEmail: normalize(req.adminUser.email || ""),
      eventId,
    });

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to delete event config" });
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
