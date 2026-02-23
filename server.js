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

function isTeamParticipationMode(eventConfig = {}) {
  const mode = String(eventConfig?.participationMode || "").trim().toLowerCase();
  const teamSize = Number(eventConfig?.teamSize || 0);
  if (teamSize > 1) return true;
  return ["team", "group", "duals", "dual"].includes(mode);
}

function normalizeTeamMode(eventConfig = {}) {
  const mode = String(eventConfig?.participationMode || "").trim().toLowerCase();
  if (["duals", "dual"].includes(mode)) return "duals";
  if (["group", "team"].includes(mode)) return "team";
  return mode || (Number(eventConfig?.teamSize || 0) > 1 ? "team" : "individual");
}

function teamCollection() {
  return adminDb.collection("teams");
}

async function getRegistrationByRegIdOrEmail(identity) {
  const raw = String(identity || "").trim();
  if (!raw) return null;
  const regIdLike = /^PZ26-/i.test(raw);
  if (regIdLike) {
    const snap = await adminDb.collection("registrations").doc(raw).get();
    if (snap.exists) return { id: snap.id, ...snap.data() };
  }
  const email = normalize(raw);
  if (!email.includes("@")) return null;
  const snap = await adminDb.collection("registrations").where("email", "==", email).limit(1).get();
  if (snap.empty) return null;
  return { id: snap.docs[0].id, ...snap.docs[0].data() };
}

async function loadTeamWithMembers(teamId) {
  const teamRef = teamCollection().doc(teamId);
  const [teamSnap, membersSnap] = await Promise.all([
    teamRef.get(),
    teamRef.collection("members").get(),
  ]);
  if (!teamSnap.exists) return null;
  const team = { id: teamSnap.id, ...teamSnap.data() };
  const members = membersSnap.docs.map(mapDoc).sort((a, b) => {
    if (a.role === "captain" && b.role !== "captain") return -1;
    if (b.role === "captain" && a.role !== "captain") return 1;
    return String(a.fullName || a.email || a.regId || "").localeCompare(String(b.fullName || b.email || b.regId || ""));
  });
  return { team, members };
}

async function userAlreadyInTeamForEvent(uid, eventId) {
  const snap = await adminDb.collectionGroup("members")
    .where("uid", "==", uid)
    .where("eventId", "==", eventId)
    .where("inviteStatus", "in", ["invited", "accepted"])
    .limit(1)
    .get();
  return !snap.empty ? snap.docs[0] : null;
}

function deriveTeamStatus(team, members = []) {
  const accepted = members.filter((m) => m.inviteStatus === "accepted").length;
  const pending = members.filter((m) => m.inviteStatus === "invited").length;
  const target = Number(team.targetSize || team.maxSize || 0);
  if ((team.status || "") === "registered" || (team.paymentStatus || "") === "paid") return "registered";
  if (target > 0 && accepted >= target && pending === 0) return "ready_for_payment";
  if (pending > 0 || accepted > 0) return "inviting";
  return "draft";
}

function teamIsLocked(team = {}) {
  const status = String(team.status || "").toLowerCase();
  const paymentStatus = String(team.paymentStatus || "").toLowerCase();
  return ["registered", "cancelled"].includes(status) || paymentStatus === "paid" || paymentStatus === "not_required";
}

function teamCountsFromMembers(members = []) {
  return {
    accepted: members.filter((m) => m.inviteStatus === "accepted").length,
    invited: members.filter((m) => m.inviteStatus === "invited").length,
    declined: members.filter((m) => m.inviteStatus === "declined").length,
  };
}

function nextTeamPatchFromMembers(team, members) {
  const counts = teamCountsFromMembers(members);
  return {
    memberCount: counts.accepted,
    status: deriveTeamStatus(team, members),
    updatedAt: admin.firestore.FieldValue.serverTimestamp(),
  };
}

async function registerAcceptedTeamMembersForEvent({
  tx,
  teamRef,
  team,
  members,
  eventConfig,
  razorpayOrderId = null,
  razorpayPaymentId = null,
}) {
  const acceptedMembers = members.filter((m) => m.inviteStatus === "accepted");
  const eventId = String(team.eventId || "");
  const category = String(team.category || eventConfig?.publicCategory || eventConfig?.category || "events");
  const eventName = String(team.eventName || eventConfig?.name || "Event");
  const eventDesc = String(eventConfig?.desc || "");
  const eventPrice = String(team.eventPrice || eventConfig?.priceLabel || "—");
  const teamAmount = parseAmount(team.amount ?? eventConfig?.amount ?? 0);
  const eventRegistryRef = adminDb.collection("eventsRegistry").doc(eventId);
  const regRefs = acceptedMembers
    .map((member) => ({
      member,
      regId: String(member.regId || "").trim(),
    }))
    .filter((x) => x.regId)
    .map((x) => ({ ...x, regRef: adminDb.collection("registrations").doc(x.regId) }));

  const regSnaps = await Promise.all(regRefs.map((x) => tx.get(x.regRef)));
  const regSnapMap = new Map();
  regRefs.forEach((x, index) => {
    regSnapMap.set(x.regId, { member: x.member, regRef: x.regRef, regSnap: regSnaps[index] });
  });

  tx.set(eventRegistryRef, {
    eventId,
    category,
    name: eventName,
    desc: eventDesc,
    priceLabel: eventPrice,
    amount: teamAmount,
    updatedAt: admin.firestore.FieldValue.serverTimestamp(),
  }, { merge: true });

  for (const member of acceptedMembers) {
    const regId = String(member.regId || "").trim();
    if (!regId) continue;
    const regBundle = regSnapMap.get(regId);
    if (!regBundle) continue;
    const { regRef, regSnap } = regBundle;
    const participantRef = eventRegistryRef.collection("participants").doc(regId);
    const eventRegistrationRef = adminDb.collection("eventRegistrations").doc(makeEventRegistrationDocId(regId, eventId));
    if (!regSnap.exists) continue;
    const reg = regSnap.data() || {};
    const current = Array.isArray(reg.registeredEvents) ? reg.registeredEvents : [];
    if (!current.some((x) => x?.id === eventId)) {
      tx.update(regRef, {
        registeredEvents: [
          ...current,
          {
            id: eventId,
            category,
            name: eventName,
            desc: eventDesc,
            price: eventPrice,
            teamId: team.teamId || teamRef.id,
            teamName: team.teamName || "",
            role: member.role || "member",
            registeredAt: admin.firestore.Timestamp.now(),
          },
        ],
      });
    }

    tx.set(participantRef, {
      regId,
      uid: reg.uid || member.uid || null,
      email: reg.email || member.email || null,
      fullName: reg.fullName || member.fullName || "",
      college: reg.college || member.college || "",
      phone: reg.phone || "",
      eventId,
      category,
      eventName,
      eventPrice,
      amount: 0,
      status: "registered",
      source: "team_server",
      teamId: team.teamId || teamRef.id,
      teamName: team.teamName || "",
      teamRole: member.role || "member",
      registeredAt: admin.firestore.FieldValue.serverTimestamp(),
    }, { merge: true });

    tx.set(eventRegistrationRef, {
      registrationDocId: makeEventRegistrationDocId(regId, eventId),
      regId,
      uid: reg.uid || member.uid || null,
      email: reg.email || member.email || "",
      fullName: reg.fullName || member.fullName || "",
      college: reg.college || member.college || "",
      phone: reg.phone || "",
      eventId,
      category,
      eventName,
      eventDesc,
      eventPrice,
      amount: 0,
      teamId: team.teamId || teamRef.id,
      teamName: team.teamName || "",
      teamRole: member.role || "member",
      teamPaymentAmount: teamAmount,
      paymentRequired: teamAmount > 0,
      paymentStatus: teamAmount > 0 ? "paid" : "not_required",
      status: "registered",
      source: "team_server",
      razorpayOrderId: razorpayOrderId || null,
      razorpayPaymentId: razorpayPaymentId || null,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    }, { merge: true });
  }
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

app.get("/teams/my", requireUser, requireFirebaseAdmin, async (req, res) => {
  try {
    const uid = String(req.userToken.uid || "");
    const [captainTeamsSnap, memberEntriesSnap] = await Promise.all([
      teamCollection().where("captainUid", "==", uid).limit(50).get(),
      adminDb.collectionGroup("members")
        .where("uid", "==", uid)
        .where("inviteStatus", "in", ["invited", "accepted"])
        .limit(100)
        .get(),
    ]);

    const teamIds = new Set();
    captainTeamsSnap.docs.forEach((d) => teamIds.add(d.id));
    memberEntriesSnap.docs.forEach((d) => {
      const teamId = String(d.data()?.teamId || d.ref.parent?.parent?.id || "");
      if (teamId) teamIds.add(teamId);
    });

    const teamBundles = await Promise.all([...teamIds].map((teamId) => loadTeamWithMembers(teamId)));
    const bundles = teamBundles.filter(Boolean);

    const eventIds = [...new Set(bundles.map((b) => String(b?.team?.eventId || "")).filter(Boolean))];
    const eventConfigMap = new Map();
    await Promise.all(eventIds.map(async (eventId) => {
      try {
        const snap = await adminDb.collection("events").doc(eventId).get();
        if (snap.exists) eventConfigMap.set(eventId, snap.data() || {});
      } catch {
        // non-fatal enrichment
      }
    }));

    const invites = [];
    const myTeams = [];
    for (const bundle of bundles) {
      const team = bundle.team;
      const members = bundle.members;
      const eventCfg = eventConfigMap.get(String(team.eventId || "")) || {};
      const effectiveAmount = parseAmount(team.amount ?? eventCfg.amount ?? 0);
      const effectivePrice = String(team.eventPrice || eventCfg.priceLabel || "—");
      const myMember = members.find((m) => m.uid === uid);
      const summary = {
        ...team,
        amount: effectiveAmount,
        eventPrice: effectivePrice,
        members,
        memberCounts: {
          accepted: members.filter((m) => m.inviteStatus === "accepted").length,
          invited: members.filter((m) => m.inviteStatus === "invited").length,
          declined: members.filter((m) => m.inviteStatus === "declined").length,
        },
        derivedStatus: deriveTeamStatus(team, members),
      };
      if (myMember?.role === "captain" || team.captainUid === uid || myMember?.inviteStatus === "accepted") {
        myTeams.push(summary);
      }
      if (myMember && myMember.role !== "captain" && myMember.inviteStatus === "invited") {
        invites.push({
          teamId: team.id,
          teamName: team.teamName,
          eventId: team.eventId,
          eventName: team.eventName,
          category: team.category,
          captainName: team.captainName || null,
          captainEmail: team.captainEmail || null,
          member: myMember,
          createdAt: team.createdAt || null,
        });
      }
    }

    myTeams.sort((a, b) => String(a.teamName || "").localeCompare(String(b.teamName || "")));
    invites.sort((a, b) => String(a.teamName || "").localeCompare(String(b.teamName || "")));

    res.json({ ok: true, myTeams, invites });
  } catch (err) {
    console.error("Load my teams failed:", err);
    res.status(500).json({ error: "Failed to load teams" });
  }
});

app.post("/teams/create", requireUser, requireFirebaseAdmin, async (req, res) => {
  try {
    const eventId = String(req.body?.eventId || "").trim();
    const teamName = String(req.body?.teamName || "").trim();
    if (!eventId) return res.status(400).json({ error: "eventId is required" });
    if (!teamName) return res.status(400).json({ error: "teamName is required" });

    const [eventSnap] = await Promise.all([
      adminDb.collection("events").doc(eventId).get(),
    ]);
    if (!eventSnap.exists) return res.status(404).json({ error: "Event not found" });
    const event = eventSnap.data() || {};
    if (event.active === false) return res.status(400).json({ error: "Event is not active" });
    if (!isTeamParticipationMode(event)) {
      return res.status(400).json({ error: "This event does not support team registration" });
    }

    const regSnapQ = await adminDb.collection("registrations").where("uid", "==", req.userToken.uid).limit(1).get();
    if (regSnapQ.empty) return res.status(400).json({ error: "Fest registration required before creating a team" });
    const reg = { id: regSnapQ.docs[0].id, ...regSnapQ.docs[0].data() };

    const existingMembership = await userAlreadyInTeamForEvent(req.userToken.uid, eventId);
    if (existingMembership) return res.status(409).json({ error: "You are already in a team for this event" });

    const targetSize = Number(event.teamSize || 0) > 1 ? Number(event.teamSize) : (normalizeTeamMode(event) === "duals" ? 2 : 2);
    const teamRef = teamCollection().doc();
    const now = admin.firestore.FieldValue.serverTimestamp();
    const teamPayload = {
      teamId: teamRef.id,
      eventId,
      eventName: String(event.name || req.body?.eventName || "Event"),
      category: String(event.publicCategory || event.category || req.body?.category || "events"),
      eventPrice: String(event.priceLabel || "—"),
      amount: parseAmount(event.amount),
      eventRegistrationType: normalizeTeamMode(event),
      captainUid: req.userToken.uid,
      captainRegId: reg.regId || reg.id,
      captainEmail: normalize(reg.email || req.userToken.email || ""),
      captainName: reg.fullName || req.userToken.name || "",
      teamName,
      status: "draft",
      paymentStatus: "not_started",
      minSize: Number(event.minTeamSize || targetSize || 2),
      maxSize: Number(event.maxTeamSize || targetSize || 2),
      targetSize,
      memberCount: 1,
      createdAt: now,
      updatedAt: now,
    };

    const captainMember = {
      teamId: teamRef.id,
      eventId,
      regId: reg.regId || reg.id,
      uid: reg.uid || req.userToken.uid,
      email: normalize(reg.email || req.userToken.email || ""),
      fullName: reg.fullName || req.userToken.name || "",
      college: reg.college || "",
      role: "captain",
      inviteStatus: "accepted",
      invitedByUid: req.userToken.uid,
      invitedAt: now,
      respondedAt: now,
      joinedAt: now,
      updatedAt: now,
    };

    await adminDb.runTransaction(async (tx) => {
      tx.set(teamRef, teamPayload);
      tx.set(teamRef.collection("members").doc(String(captainMember.regId)), captainMember);
    });

    await writeAdminAuditLog("team_created", {
      source: "teams_create_api",
      actorEmail: normalize(req.userToken.email || ""),
      teamId: teamRef.id,
      eventId,
      captainRegId: reg.regId || reg.id,
    });

    const bundle = await loadTeamWithMembers(teamRef.id);
    res.json({ ok: true, team: bundle?.team || { id: teamRef.id, ...teamPayload }, members: bundle?.members || [captainMember] });
  } catch (err) {
    console.error("Create team failed:", err);
    res.status(500).json({ error: err?.message || "Failed to create team" });
  }
});

app.post("/teams/invite-member", requireUser, requireFirebaseAdmin, async (req, res) => {
  try {
    const teamId = String(req.body?.teamId || "").trim();
    const memberIdentity = String(req.body?.memberIdentity || "").trim();
    if (!teamId || !memberIdentity) return res.status(400).json({ error: "teamId and memberIdentity are required" });

    const teamRef = teamCollection().doc(teamId);
    const teamSnap = await teamRef.get();
    if (!teamSnap.exists) return res.status(404).json({ error: "Team not found" });
    const team = teamSnap.data() || {};
    if (team.captainUid !== req.userToken.uid) return res.status(403).json({ error: "Only captain can invite members" });
    if ((team.paymentStatus || "") === "paid" || (team.status || "").includes("registered")) {
      return res.status(400).json({ error: "Team is locked after registration" });
    }

    const targetReg = await getRegistrationByRegIdOrEmail(memberIdentity);
    if (!targetReg) return res.status(404).json({ error: "Member fest registration not found" });
    if ((targetReg.uid || "") === req.userToken.uid) return res.status(400).json({ error: "Captain is already in the team" });

    const conflicting = await userAlreadyInTeamForEvent(targetReg.uid, team.eventId);
    if (conflicting) {
      const conflictTeamId = conflicting.data()?.teamId || conflicting.ref.parent?.parent?.id || null;
      if (conflictTeamId && conflictTeamId !== teamId) {
        return res.status(409).json({ error: "Member is already in another team for this event" });
      }
    }

    const memberRef = teamRef.collection("members").doc(String(targetReg.regId || targetReg.id));

    await adminDb.runTransaction(async (tx) => {
      const [freshTeamSnap, memberSnap, allMembersSnap] = await Promise.all([
        tx.get(teamRef),
        tx.get(memberRef),
        tx.get(teamRef.collection("members")),
      ]);
      if (!freshTeamSnap.exists) throw new Error("Team not found");
      const freshTeam = freshTeamSnap.data() || {};
      const members = allMembersSnap.docs.map((d) => d.data() || {});
      const acceptedCount = members.filter((m) => m.inviteStatus === "accepted").length;
      const invitedCount = members.filter((m) => m.inviteStatus === "invited").length;
      const currentActiveCount = acceptedCount + invitedCount;
      const maxSize = Number(freshTeam.maxSize || freshTeam.targetSize || 0);
      if (maxSize > 0 && currentActiveCount >= maxSize && !memberSnap.exists) {
        throw new Error("Team is full");
      }

      tx.set(memberRef, {
        teamId,
        eventId: freshTeam.eventId,
        regId: targetReg.regId || targetReg.id,
        uid: targetReg.uid || null,
        email: normalize(targetReg.email || ""),
        fullName: targetReg.fullName || "",
        college: targetReg.college || "",
        role: "member",
        inviteStatus: "invited",
        invitedByUid: req.userToken.uid,
        invitedAt: admin.firestore.FieldValue.serverTimestamp(),
        respondedAt: null,
        joinedAt: null,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      }, { merge: true });

      tx.update(teamRef, {
        status: "inviting",
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    });

    const bundle = await loadTeamWithMembers(teamId);
    res.json({ ok: true, team: bundle?.team, members: bundle?.members });
  } catch (err) {
    console.error("Invite member failed:", err);
    res.status(500).json({ error: err?.message || "Failed to invite member" });
  }
});

app.post("/teams/respond-invite", requireUser, requireFirebaseAdmin, async (req, res) => {
  try {
    const teamId = String(req.body?.teamId || "").trim();
    const action = String(req.body?.action || "").trim().toLowerCase();
    if (!teamId || !["accept", "reject"].includes(action)) {
      return res.status(400).json({ error: "teamId and valid action are required" });
    }

    const regSnap = await adminDb.collection("registrations").where("uid", "==", req.userToken.uid).limit(1).get();
    if (regSnap.empty) return res.status(400).json({ error: "Fest registration required" });
    const reg = { id: regSnap.docs[0].id, ...regSnap.docs[0].data() };
    const memberRef = teamCollection().doc(teamId).collection("members").doc(String(reg.regId || reg.id));
    const teamRef = teamCollection().doc(teamId);
    const teamSnapPre = await teamRef.get();
    if (!teamSnapPre.exists) return res.status(404).json({ error: "Team not found" });
    const preTeam = teamSnapPre.data() || {};
    const existingMembershipElsewhere = action === "accept"
      ? await userAlreadyInTeamForEvent(req.userToken.uid, preTeam.eventId || "")
      : null;

    await adminDb.runTransaction(async (tx) => {
      const [teamSnap, memberSnap, allMembersSnap] = await Promise.all([
        tx.get(teamRef),
        tx.get(memberRef),
        tx.get(teamRef.collection("members")),
      ]);
      if (!teamSnap.exists) throw new Error("Team not found");
      if (!memberSnap.exists) throw new Error("Invite not found");
      const team = teamSnap.data() || {};
      const member = memberSnap.data() || {};
      if (member.role === "captain") throw new Error("Captain cannot respond to invite");
      if (member.uid && member.uid !== req.userToken.uid) throw new Error("Invite owner mismatch");
      if (member.inviteStatus !== "invited" && action === "accept") throw new Error("Invite is not pending");
      if ((team.paymentStatus || "") === "paid") throw new Error("Team is locked");

      if (action === "accept") {
        const conflict = allMembersSnap.docs.find((d) => {
          const data = d.data() || {};
          return data.uid === req.userToken.uid && d.id !== memberSnap.id && ["accepted", "invited"].includes(String(data.inviteStatus || ""));
        });
        if (conflict) throw new Error("Duplicate team membership");
        const otherTeamId = existingMembershipElsewhere?.data()?.teamId || existingMembershipElsewhere?.ref?.parent?.parent?.id || null;
        if (otherTeamId && otherTeamId !== teamId) throw new Error("You are already in another team for this event");
      }

      tx.update(memberRef, {
        inviteStatus: action === "accept" ? "accepted" : "declined",
        respondedAt: admin.firestore.FieldValue.serverTimestamp(),
        joinedAt: action === "accept" ? admin.firestore.FieldValue.serverTimestamp() : null,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });

      const membersAfter = allMembersSnap.docs.map((d) => (d.id === memberSnap.id
        ? { ...(d.data() || {}), inviteStatus: action === "accept" ? "accepted" : "declined" }
        : (d.data() || {})));
      const acceptedCount = membersAfter.filter((m) => m.inviteStatus === "accepted").length;
      const pendingCount = membersAfter.filter((m) => m.inviteStatus === "invited").length;
      const target = Number(team.targetSize || team.maxSize || 0);
      const nextStatus = acceptedCount >= target && pendingCount === 0 ? "ready_for_payment" : "inviting";

      tx.update(teamRef, {
        memberCount: acceptedCount,
        status: nextStatus,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    });

    const bundle = await loadTeamWithMembers(teamId);
    res.json({ ok: true, action, team: bundle?.team, members: bundle?.members });
  } catch (err) {
    console.error("Respond invite failed:", err);
    res.status(500).json({ error: err?.message || "Failed to respond to invite" });
  }
});

app.post("/teams/remove-member", requireUser, requireFirebaseAdmin, async (req, res) => {
  try {
    const teamId = String(req.body?.teamId || "").trim();
    const memberRegId = String(req.body?.memberRegId || "").trim();
    if (!teamId || !memberRegId) return res.status(400).json({ error: "teamId and memberRegId are required" });

    const teamRef = teamCollection().doc(teamId);
    const memberRef = teamRef.collection("members").doc(memberRegId);

    await adminDb.runTransaction(async (tx) => {
      const [teamSnap, memberSnap, allMembersSnap] = await Promise.all([
        tx.get(teamRef),
        tx.get(memberRef),
        tx.get(teamRef.collection("members")),
      ]);
      if (!teamSnap.exists) throw new Error("Team not found");
      if (!memberSnap.exists) throw new Error("Member not found");
      const team = teamSnap.data() || {};
      if (String(team.captainUid || "") !== String(req.userToken.uid || "")) throw new Error("Only captain can remove members");
      if (teamIsLocked(team)) throw new Error("Team is locked");

      const member = memberSnap.data() || {};
      if (member.role === "captain") throw new Error("Transfer captain first");
      if (!["invited", "accepted"].includes(String(member.inviteStatus || ""))) {
        throw new Error("Member is not active in team");
      }

      tx.update(memberRef, {
        inviteStatus: "removed",
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        respondedAt: admin.firestore.FieldValue.serverTimestamp(),
      });

      const membersAfter = allMembersSnap.docs.map((d) => (
        d.id === memberRegId
          ? { ...(d.data() || {}), inviteStatus: "removed" }
          : (d.data() || {})
      ));
      tx.update(teamRef, nextTeamPatchFromMembers(team, membersAfter));
    });

    const bundle = await loadTeamWithMembers(teamId);
    res.json({ ok: true, team: bundle?.team, members: bundle?.members });
  } catch (err) {
    console.error("Remove member failed:", err);
    res.status(500).json({ error: err?.message || "Failed to remove member" });
  }
});

app.post("/teams/transfer-captain", requireUser, requireFirebaseAdmin, async (req, res) => {
  try {
    const teamId = String(req.body?.teamId || "").trim();
    const memberRegId = String(req.body?.memberRegId || "").trim();
    if (!teamId || !memberRegId) return res.status(400).json({ error: "teamId and memberRegId are required" });

    const teamRef = teamCollection().doc(teamId);
    const targetRef = teamRef.collection("members").doc(memberRegId);

    await adminDb.runTransaction(async (tx) => {
      const [teamSnap, targetSnap, allMembersSnap] = await Promise.all([
        tx.get(teamRef),
        tx.get(targetRef),
        tx.get(teamRef.collection("members")),
      ]);
      if (!teamSnap.exists) throw new Error("Team not found");
      if (!targetSnap.exists) throw new Error("Target member not found");
      const team = teamSnap.data() || {};
      if (String(team.captainUid || "") !== String(req.userToken.uid || "")) throw new Error("Only captain can transfer captaincy");
      if (teamIsLocked(team)) throw new Error("Team is locked");

      const target = targetSnap.data() || {};
      if (target.role === "captain") throw new Error("Member is already captain");
      if (target.inviteStatus !== "accepted") throw new Error("Target member must accept invite first");

      const oldCaptainDoc = allMembersSnap.docs.find((d) => (d.data() || {}).role === "captain");
      if (!oldCaptainDoc) throw new Error("Captain member record not found");

      tx.update(oldCaptainDoc.ref, {
        role: "member",
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });
      tx.update(targetRef, {
        role: "captain",
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });
      tx.update(teamRef, {
        captainUid: target.uid || null,
        captainRegId: target.regId || memberRegId,
        captainEmail: target.email || null,
        captainName: target.fullName || "",
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    });

    const bundle = await loadTeamWithMembers(teamId);
    res.json({ ok: true, team: bundle?.team, members: bundle?.members });
  } catch (err) {
    console.error("Transfer captain failed:", err);
    res.status(500).json({ error: err?.message || "Failed to transfer captain" });
  }
});

app.post("/teams/leave", requireUser, requireFirebaseAdmin, async (req, res) => {
  try {
    const teamId = String(req.body?.teamId || "").trim();
    if (!teamId) return res.status(400).json({ error: "teamId is required" });

    const regSnap = await adminDb.collection("registrations").where("uid", "==", req.userToken.uid).limit(1).get();
    if (regSnap.empty) return res.status(400).json({ error: "Fest registration required" });
    const reg = { id: regSnap.docs[0].id, ...regSnap.docs[0].data() };
    const memberRegId = String(reg.regId || reg.id);
    const teamRef = teamCollection().doc(teamId);
    const memberRef = teamRef.collection("members").doc(memberRegId);

    let deletedTeam = false;
    await adminDb.runTransaction(async (tx) => {
      const [teamSnap, memberSnap, allMembersSnap] = await Promise.all([
        tx.get(teamRef),
        tx.get(memberRef),
        tx.get(teamRef.collection("members")),
      ]);
      if (!teamSnap.exists) throw new Error("Team not found");
      if (!memberSnap.exists) throw new Error("You are not part of this team");
      const team = teamSnap.data() || {};
      if (teamIsLocked(team)) throw new Error("Team is locked");
      const member = memberSnap.data() || {};
      if (member.uid && String(member.uid) !== String(req.userToken.uid)) throw new Error("Member mismatch");

      const allMembers = allMembersSnap.docs.map((d) => ({ id: d.id, ...(d.data() || {}) }));
      const activeOthers = allMembers.filter((m) =>
        m.id !== memberRegId && ["accepted", "invited"].includes(String(m.inviteStatus || ""))
      );

      if (member.role === "captain" && activeOthers.length > 0) {
        throw new Error("Transfer captain before leaving the team");
      }

      if (member.role === "captain" && activeOthers.length === 0) {
        allMembersSnap.docs.forEach((d) => tx.delete(d.ref));
        tx.delete(teamRef);
        deletedTeam = true;
        return;
      }

      tx.update(memberRef, {
        inviteStatus: "left",
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        respondedAt: admin.firestore.FieldValue.serverTimestamp(),
      });
      const membersAfter = allMembers.map((m) => (
        m.id === memberRegId ? { ...m, inviteStatus: "left" } : m
      ));
      tx.update(teamRef, nextTeamPatchFromMembers(team, membersAfter));
    });

    if (deletedTeam) return res.json({ ok: true, deletedTeam: true, teamId });
    const bundle = await loadTeamWithMembers(teamId);
    res.json({ ok: true, team: bundle?.team, members: bundle?.members, deletedTeam: false });
  } catch (err) {
    console.error("Leave team failed:", err);
    res.status(500).json({ error: err?.message || "Failed to leave team" });
  }
});

app.post("/teams/finalize-payment", requireUser, requireFirebaseAdmin, async (req, res) => {
  try {
    const teamId = String(req.body?.teamId || "").trim();
    const orderId = String(req.body?.orderId || "").trim();
    const paymentId = String(req.body?.paymentId || "").trim();
    const signature = String(req.body?.signature || "").trim();
    if (!teamId) return res.status(400).json({ error: "teamId is required" });

    const teamRef = teamCollection().doc(teamId);
    const teamSnap = await teamRef.get();
    if (!teamSnap.exists) return res.status(404).json({ error: "Team not found" });
    const team = teamSnap.data() || {};
    const eventSnap = team.eventId ? await adminDb.collection("events").doc(String(team.eventId)).get() : null;
    if (String(team.captainUid || "") !== String(req.userToken.uid || "")) {
      return res.status(403).json({ error: "Only captain can pay for the team" });
    }

    const eventConfig = eventSnap?.exists ? (eventSnap.data() || {}) : {};
    const teamAmount = parseAmount(team.amount ?? eventConfig?.amount ?? 0);
    if (teamAmount > 0) {
      if (!orderId || !paymentId || !signature) {
        return res.status(400).json({ error: "Missing payment proof" });
      }
      if (!verifyRazorpaySignature(orderId, paymentId, signature)) {
        return res.status(400).json({ error: "Invalid Razorpay signature" });
      }
    }

    let alreadyPaid = false;
    await adminDb.runTransaction(async (tx) => {
      const [freshTeamSnap, membersSnap] = await Promise.all([
        tx.get(teamRef),
        tx.get(teamRef.collection("members")),
      ]);
      if (!freshTeamSnap.exists) throw new Error("Team not found");
      const freshTeam = freshTeamSnap.data() || {};
      if (String(freshTeam.captainUid || "") !== String(req.userToken.uid || "")) {
        throw new Error("Only captain can pay for the team");
      }
      if ((freshTeam.paymentStatus || "") === "paid") {
        alreadyPaid = true;
        return;
      }

      const members = membersSnap.docs.map((d) => ({ id: d.id, ...d.data() }));
      const accepted = members.filter((m) => m.inviteStatus === "accepted");
      const pending = members.filter((m) => m.inviteStatus === "invited");
      const target = Number(freshTeam.targetSize || freshTeam.maxSize || 0);
      if (!accepted.length) throw new Error("No accepted team members");
      if (target > 0 && accepted.length < target) {
        throw new Error(`Team roster incomplete (${accepted.length}/${target})`);
      }
      if (pending.length > 0) {
        throw new Error("Pending invites must be resolved before payment");
      }

      await registerAcceptedTeamMembersForEvent({
        tx,
        teamRef,
        team: { ...freshTeam, teamId: freshTeam.teamId || teamRef.id },
        members,
        eventConfig,
        razorpayOrderId: orderId || null,
        razorpayPaymentId: paymentId || null,
      });

      tx.set(teamRef, {
        status: "registered",
        paymentStatus: teamAmount > 0 ? "paid" : "not_required",
        memberCount: accepted.length,
        amount: teamAmount,
        eventPrice: String(freshTeam.eventPrice || eventConfig?.priceLabel || "—"),
        paidAt: teamAmount > 0 ? admin.firestore.FieldValue.serverTimestamp() : null,
        razorpayOrderId: orderId || null,
        razorpayPaymentId: paymentId || null,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      }, { merge: true });
    });

    if (teamAmount > 0 && paymentId) {
      try {
        await reconcileEventPayment({
          paymentId: paymentId || null,
          orderId: orderId || null,
          source: "team_finalize_api",
        });
      } catch (err) {
        console.error("Team payment reconcile warning:", err);
      }
    }

    await writeAdminAuditLog("team_payment_finalize", {
      source: "teams_finalize_payment_api",
      actorEmail: normalize(req.userToken.email || ""),
      teamId,
      orderId: orderId || null,
      paymentId: paymentId || null,
      alreadyPaid,
    });

    const bundle = await loadTeamWithMembers(teamId);
    const derivedStatus = bundle ? deriveTeamStatus(bundle.team, bundle.members) : null;
    res.json({
      ok: true,
      alreadyPaid,
      team: bundle?.team || { id: teamId, ...team },
      members: bundle?.members || [],
      derivedStatus,
      paymentStatus: teamAmount > 0 ? "paid" : "not_required",
    });
  } catch (err) {
    console.error("Team finalize payment failed:", err);
    res.status(500).json({ error: err?.message || "Failed to finalize team payment" });
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

app.get("/admin/teams", requireAdmin, requireFirebaseAdmin, async (req, res) => {
  try {
    const limitN = Math.min(500, Math.max(1, Number(req.query.limit || 200)));
    const snap = await adminDb.collection("teams").orderBy("createdAt", "desc").limit(limitN).get();
    const rows = await Promise.all(snap.docs.map(async (teamDoc) => {
      const team = { id: teamDoc.id, ...teamDoc.data() };
      const membersSnap = await teamDoc.ref.collection("members").get();
      const members = membersSnap.docs.map(mapDoc);
      return { ...team, members };
    }));
    res.json({ ok: true, rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to load teams" });
  }
});

app.post("/admin/team-status", requireAdmin, requireFirebaseAdmin, async (req, res) => {
  try {
    const teamId = String(req.body?.teamId || "").trim();
    const status = req.body?.status == null ? null : String(req.body.status).trim();
    const paymentStatus = req.body?.paymentStatus == null ? null : String(req.body.paymentStatus).trim();
    if (!teamId) return res.status(400).json({ error: "teamId is required" });
    if (!status && !paymentStatus) return res.status(400).json({ error: "No team updates provided" });

    const update = { updatedAt: admin.firestore.FieldValue.serverTimestamp() };
    if (status) update.status = status;
    if (paymentStatus) update.paymentStatus = paymentStatus;

    await adminDb.collection("teams").doc(teamId).set(update, { merge: true });
    await writeAdminAuditLog("admin_team_status_update", {
      source: "admin_team_status_api",
      actorEmail: normalize(req.adminUser?.email || ""),
      teamId,
      status: status || null,
      paymentStatus: paymentStatus || null,
    });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to update team status" });
  }
});

app.post("/admin/team-control", requireAdmin, requireFirebaseAdmin, async (req, res) => {
  try {
    const teamId = String(req.body?.teamId || "").trim();
    const action = String(req.body?.action || "").trim().toLowerCase();
    if (!teamId) return res.status(400).json({ error: "teamId is required" });
    if (!["unlock", "cancel", "force_register", "delete"].includes(action)) {
      return res.status(400).json({ error: "Invalid team control action" });
    }

    const teamRef = adminDb.collection("teams").doc(teamId);
    const preSnap = await teamRef.get();
    if (!preSnap.exists) return res.status(404).json({ error: "Team not found" });
    const preTeam = preSnap.data() || {};
    const eventSnap = preTeam.eventId ? await adminDb.collection("events").doc(String(preTeam.eventId)).get() : null;
    const eventConfig = eventSnap?.exists ? (eventSnap.data() || {}) : {};

    if (action === "delete") {
      const membersSnap = await teamRef.collection("members").get();
      const batch = adminDb.batch();
      membersSnap.docs.forEach((d) => batch.delete(d.ref));
      batch.delete(teamRef);
      const teamEventRegs = await adminDb.collection("eventRegistrations").where("teamId", "==", teamId).limit(500).get();
      teamEventRegs.docs.forEach((d) => {
        batch.set(d.ref, {
          status: "cancelled",
          teamDeleted: true,
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        }, { merge: true });
      });
      await batch.commit();
      await writeAdminAuditLog("admin_team_delete", {
        source: "admin_team_control_api",
        actorEmail: normalize(req.adminUser?.email || ""),
        teamId,
      });
      return res.json({ ok: true, action, deleted: true });
    }

    if (action === "cancel") {
      await teamRef.set({
        status: "cancelled",
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      }, { merge: true });
      await writeAdminAuditLog("admin_team_cancel", {
        source: "admin_team_control_api",
        actorEmail: normalize(req.adminUser?.email || ""),
        teamId,
      });
      return res.json({ ok: true, action });
    }

    if (action === "unlock") {
      await adminDb.runTransaction(async (tx) => {
        const [teamSnap, membersSnap] = await Promise.all([
          tx.get(teamRef),
          tx.get(teamRef.collection("members")),
        ]);
        if (!teamSnap.exists) throw new Error("Team not found");
        const team = teamSnap.data() || {};
        const members = membersSnap.docs.map((d) => d.data() || {});
        const derived = deriveTeamStatus({ ...team, paymentStatus: "pending", status: "draft" }, members);
        const amount = parseAmount(team.amount ?? eventConfig?.amount ?? 0);
        tx.set(teamRef, {
          status: derived,
          paymentStatus: amount > 0 ? "pending" : "not_started",
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        }, { merge: true });
      });
      await writeAdminAuditLog("admin_team_unlock", {
        source: "admin_team_control_api",
        actorEmail: normalize(req.adminUser?.email || ""),
        teamId,
      });
      return res.json({ ok: true, action });
    }

    if (action === "force_register") {
      await adminDb.runTransaction(async (tx) => {
        const [teamSnap, membersSnap] = await Promise.all([
          tx.get(teamRef),
          tx.get(teamRef.collection("members")),
        ]);
        if (!teamSnap.exists) throw new Error("Team not found");
        const team = teamSnap.data() || {};
        const members = membersSnap.docs.map((d) => ({ id: d.id, ...d.data() }));
        const accepted = members.filter((m) => m.inviteStatus === "accepted");
        const pending = members.filter((m) => m.inviteStatus === "invited");
        if (!accepted.length) throw new Error("No accepted members in team");
        if (pending.length) throw new Error("Resolve pending invites before force register");

        await registerAcceptedTeamMembersForEvent({
          tx,
          teamRef,
          team: { ...team, teamId },
          members,
          eventConfig,
          razorpayOrderId: team.razorpayOrderId || null,
          razorpayPaymentId: team.razorpayPaymentId || null,
        });

        const amount = parseAmount(team.amount ?? eventConfig?.amount ?? 0);
        tx.set(teamRef, {
          status: "registered",
          paymentStatus: amount > 0
            ? (String(team.paymentStatus || "").toLowerCase() === "paid" ? "paid" : "manual_override")
            : "not_required",
          memberCount: accepted.length,
          amount,
          eventPrice: String(team.eventPrice || eventConfig?.priceLabel || "—"),
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
          forceRegisteredAt: admin.firestore.FieldValue.serverTimestamp(),
        }, { merge: true });
      });
      await writeAdminAuditLog("admin_team_force_register", {
        source: "admin_team_control_api",
        actorEmail: normalize(req.adminUser?.email || ""),
        teamId,
      });
      return res.json({ ok: true, action });
    }
  } catch (err) {
    console.error("Admin team control failed:", err);
    res.status(500).json({ error: err?.message || "Failed to perform team action" });
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
