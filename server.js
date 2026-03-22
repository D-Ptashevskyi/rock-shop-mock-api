const express = require("express");
const crypto = require("crypto");

const app = express();

app.set("trust proxy", true);
app.use(express.json({ limit: "1mb" }));

const APP_VERSION = "fix-2026-03-22-v2";

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const nowIso = () => new Date().toISOString();

function makeId(prefix) {
  return `${prefix}_${crypto.randomBytes(6).toString("hex")}_${Date.now()}`;
}

function hashPassword(password) {
  return crypto.createHash("sha256").update(String(password)).digest("hex");
}

function makeToken(role = "user") {
  return `mock_${role}_${crypto.randomBytes(12).toString("hex")}_${Date.now()}`;
}

function requestId() {
  return crypto.randomBytes(8).toString("hex");
}

function sendError(res, status, error, message, details) {
  const body = {
    error,
    message,
    ts: nowIso(),
    requestId: res.locals.requestId,
  };

  if (details !== undefined) {
    body.details = details;
  }

  return res.status(status).json(body);
}

function sendUnauthorized(res, message, authError = "invalid_token") {
  res.setHeader(
    "WWW-Authenticate",
    `Bearer realm="rock-shop", error="${authError}", error_description="${message}"`
  );

  return sendError(res, 401, "Unauthorized", message);
}

app.use((req, res, next) => {
  res.locals.requestId = requestId();
  res.setHeader("X-Request-Id", res.locals.requestId);
  next();
});

app.use((err, req, res, next) => {
  if (err && err.type === "entity.parse.failed") {
    return sendError(res, 400, "Bad Request", "Invalid JSON body");
  }

  next(err);
});

let db = {
  usersByEmail: new Map(),
  sessionsByToken: new Map(),
  ordersByUserId: new Map(),
  products: [
    { id: "p1", title: "Vintage Guitar (Replica)", price: 1299, tags: ["guitar", "vintage", "stage"] },
    { id: "p2", title: "Tour Bus Espresso Machine", price: 299, tags: ["tour", "coffee", "backstage"] },
    { id: "p3", title: "Chrome Skull Mic Stand", price: 199, tags: ["microphone", "stage", "metal"] },
    { id: "p4", title: "Backstage Pass Lanyard Kit", price: 39, tags: ["backstage", "crew", "pass"] },
  ],
};

function seedAdmin() {
  const email = "admin@rock.shop";

  if (db.usersByEmail.has(email)) {
    return;
  }

  db.usersByEmail.set(email, {
    id: makeId("u"),
    email,
    name: "Admin",
    passwordHash: hashPassword("admin123"),
    role: "admin",
    createdAt: nowIso(),
  });
}

seedAdmin();

const DEFAULTS = {
  maintenance: false,
  maintenanceRetryAfterSec: 120,
  rate: {
    enabled: true,
    windowMs: 10000,
    max: 100,
  },
};

const config = {
  maintenance: DEFAULTS.maintenance,
  maintenanceRetryAfterSec: DEFAULTS.maintenanceRetryAfterSec,
  rate: { ...DEFAULTS.rate },
};

const rateState = {
  hits: new Map(),
};

app.use(async (req, res, next) => {
  const ms = Number(req.query.ms);

  if (Number.isFinite(ms) && ms > 0) {
    await sleep(ms);
  }

  next();
});

app.use((req, res, next) => {
  const allowed = [
    "/health",
    "/ping",
    "/__reset",
    "/__config",
    "/cache",
    "/moved-permanently",
    "/found",
    "/error",
    "/bad-gateway",
    "/unavailable",
    "/gateway-timeout",
  ];

  if (!config.maintenance || allowed.includes(req.path)) {
    return next();
  }

  res.setHeader("Retry-After", String(config.maintenanceRetryAfterSec));
  return sendError(res, 503, "Service Unavailable", "Maintenance mode");
});

function getStableClientId(req) {
  const clientId = req.get("X-Client-Id");

  if (clientId) {
    return `cid:${String(clientId).trim()}`;
  }

  const raw =
    req.ips && req.ips.length
      ? req.ips[0]
      : req.ip || req.socket?.remoteAddress || "unknown";

  return `ip:${String(raw).trim().replace(/^::ffff:/, "")}`;
}

function rateLimit(req, res, next) {
  if (!config.rate.enabled) {
    return next();
  }

  const excluded = ["/health", "/ping", "/__reset", "/__config"];

  if (excluded.includes(req.path)) {
    return next();
  }

  const clientKey = getStableClientId(req);
  const key = `${clientKey}:${req.method}:${req.path}`;
  const t = Date.now();
  const cur = rateState.hits.get(key);

  if (!cur || t > cur.resetAt) {
    rateState.hits.set(key, {
      count: 1,
      resetAt: t + config.rate.windowMs,
    });

    res.setHeader("X-RateLimit-Limit", String(config.rate.max));
    res.setHeader("X-RateLimit-Remaining", String(config.rate.max - 1));
    res.setHeader("X-RateLimit-Reset", String(Math.ceil((t + config.rate.windowMs) / 1000)));

    return next();
  }

  if (cur.count >= config.rate.max) {
    const retryAfterSec = Math.max(1, Math.ceil((cur.resetAt - t) / 1000));

    res.setHeader("Retry-After", String(retryAfterSec));
    res.setHeader("X-RateLimit-Limit", String(config.rate.max));
    res.setHeader("X-RateLimit-Remaining", "0");
    res.setHeader("X-RateLimit-Reset", String(Math.ceil(cur.resetAt / 1000)));

    return sendError(
      res,
      429,
      "Too Many Requests",
      `Rate limit exceeded. Try again in ~${retryAfterSec}s`
    );
  }

  cur.count += 1;
  rateState.hits.set(key, cur);

  res.setHeader("X-RateLimit-Limit", String(config.rate.max));
  res.setHeader("X-RateLimit-Remaining", String(config.rate.max - cur.count));
  res.setHeader("X-RateLimit-Reset", String(Math.ceil(cur.resetAt / 1000)));

  next();
}

app.use(rateLimit);

function requireAuth(req, res, next) {
  const h = req.headers.authorization || "";
  const m = h.match(/^Bearer\s+(.+)$/i);

  if (!m) {
    return sendUnauthorized(res, "Missing Bearer token", "invalid_request");
  }

  const token = m[1];
  const session = db.sessionsByToken.get(token);

  if (!session) {
    return sendUnauthorized(res, "Invalid token", "invalid_token");
  }

  req.session = session;
  next();
}

function requireAdmin(req, res, next) {
  if (req.session?.role !== "admin") {
    return sendError(res, 403, "Forbidden", "Admin role required");
  }

  next();
}

app.get("/ping", (req, res) => {
  res.status(200).send("pong");
});

app.get("/health", (req, res) => {
  res.status(200).json({
    ok: true,
    version: APP_VERSION,
    service: "rock-star-shop-mock-api",
    maintenance: config.maintenance,
    rate: config.rate,
    ts: nowIso(),
    requestId: res.locals.requestId,
  });
});

app.post("/__reset", (req, res) => {
  db.usersByEmail = new Map(
    [...db.usersByEmail.entries()].filter(([_, user]) => user.role === "admin")
  );
  db.sessionsByToken.clear();
  db.ordersByUserId.clear();
  rateState.hits.clear();

  seedAdmin();

  config.maintenance = DEFAULTS.maintenance;
  config.maintenanceRetryAfterSec = DEFAULTS.maintenanceRetryAfterSec;
  config.rate = { ...DEFAULTS.rate };

  return res.status(200).json({
    message: "Reset done",
    config,
    ts: nowIso(),
    requestId: res.locals.requestId,
  });
});

app.post("/__config", (req, res) => {
  const { maintenance, maintenanceRetryAfterSec, rate } = req.body || {};

  if (typeof maintenance === "boolean") {
    config.maintenance = maintenance;
  }

  if (Number.isFinite(maintenanceRetryAfterSec) && maintenanceRetryAfterSec >= 1) {
    config.maintenanceRetryAfterSec = Math.floor(maintenanceRetryAfterSec);
  }

  if (rate && typeof rate === "object") {
    if (typeof rate.enabled === "boolean") {
      config.rate.enabled = rate.enabled;
    }

    if (Number.isFinite(rate.windowMs) && rate.windowMs >= 1000) {
      config.rate.windowMs = rate.windowMs;
    }

    if (Number.isFinite(rate.max) && rate.max >= 1) {
      config.rate.max = rate.max;
    }
  }

  rateState.hits.clear();

  return res.status(200).json({
    message: "Config updated",
    config,
    ts: nowIso(),
    requestId: res.locals.requestId,
  });
});

app.post("/auth/register", (req, res) => {
  const { email, password, name } = req.body || {};

  if (typeof email !== "string" || typeof password !== "string") {
    return sendError(res, 400, "Bad Request", "email and password are required");
  }

  const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

  if (!emailOk) {
    return sendError(
      res,
      422,
      "Unprocessable Entity",
      "Invalid email format",
      { field: "email" }
    );
  }

  if (password.length < 6) {
    return sendError(
      res,
      422,
      "Unprocessable Entity",
      "Password must be at least 6 characters",
      { field: "password" }
    );
  }

  if (db.usersByEmail.has(email)) {
    return sendError(res, 409, "Conflict", "User with this email already exists");
  }

  const user = {
    id: makeId("u"),
    email,
    name: typeof name === "string" && name.trim() ? name.trim() : "Rock Star",
    passwordHash: hashPassword(password),
    role: "user",
    createdAt: nowIso(),
  };

  db.usersByEmail.set(email, user);

  res.setHeader("Location", `/users/${user.id}`);

  return res.status(201).json({
    message: "Created",
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      createdAt: user.createdAt,
    },
    ts: nowIso(),
    requestId: res.locals.requestId,
  });
});

app.post("/auth/login", (req, res) => {
  const { email, password } = req.body || {};

  if (typeof email !== "string" || typeof password !== "string") {
    return sendError(res, 400, "Bad Request", "email and password are required");
  }

  const user = db.usersByEmail.get(email);

  if (!user || user.passwordHash !== hashPassword(password)) {
    return sendUnauthorized(res, "Invalid credentials", "invalid_token");
  }

  const token = makeToken(user.role);

  db.sessionsByToken.set(token, {
    userId: user.id,
    role: user.role,
    email: user.email,
  });

  return res.status(200).json({
    message: "Logged in",
    tokenType: "Bearer",
    token,
    role: user.role,
    userId: user.id,
    ts: nowIso(),
    requestId: res.locals.requestId,
  });
});

app.post("/auth/logout", requireAuth, (req, res) => {
  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  db.sessionsByToken.delete(token);
  return res.status(204).send();
});

app.get("/shop/profile", requireAuth, (req, res) => {
  const user = db.usersByEmail.get(req.session.email);

  if (!user) {
    return sendUnauthorized(res, "Session user not found", "invalid_token");
  }

  return res.status(200).json({
    message: "OK",
    profile: {
      userId: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      createdAt: user.createdAt,
      store: "Rock Star Shop",
    },
    ts: nowIso(),
    requestId: res.locals.requestId,
  });
});

app.get("/shop/products", requireAuth, (req, res) => {
  return res.status(200).json({
    message: "OK",
    products: db.products,
    ts: nowIso(),
    requestId: res.locals.requestId,
  });
});

app.post("/shop/orders", requireAuth, (req, res) => {
  const { items } = req.body || {};

  if (!Array.isArray(items)) {
    return sendError(
      res,
      400,
      "Bad Request",
      "items must be an array like [{productId, qty}]"
    );
  }

  if (items.length === 0) {
    return sendError(res, 422, "Unprocessable Entity", "items cannot be empty");
  }

  let total = 0;
  const normalized = [];

  for (const it of items) {
    const productId = it?.productId;
    const qty = Number(it?.qty);

    if (typeof productId !== "string" || !Number.isFinite(qty) || qty <= 0) {
      return sendError(
        res,
        422,
        "Unprocessable Entity",
        "each item must have productId (string) and qty (number > 0)"
      );
    }

    const product = db.products.find((p) => p.id === productId);

    if (!product) {
      return sendError(res, 404, "Not Found", `Product not found: ${productId}`);
    }

    total += product.price * qty;
    normalized.push({
      productId,
      qty,
      unitPrice: product.price,
      title: product.title,
    });
  }

  const order = {
    id: makeId("o"),
    items: normalized,
    total,
    createdAt: nowIso(),
    status: "created",
  };

  const list = db.ordersByUserId.get(req.session.userId) || [];
  list.push(order);
  db.ordersByUserId.set(req.session.userId, list);

  res.setHeader("Location", `/shop/orders/${order.id}`);

  return res.status(201).json({
    message: "Created",
    order,
    ts: nowIso(),
    requestId: res.locals.requestId,
  });
});

app.get("/shop/orders", requireAuth, (req, res) => {
  const list = db.ordersByUserId.get(req.session.userId) || [];

  return res.status(200).json({
    message: "OK",
    orders: list,
    ts: nowIso(),
    requestId: res.locals.requestId,
  });
});

app.delete("/shop/orders/:orderId", requireAuth, (req, res) => {
  const orderId = req.params.orderId;
  const list = db.ordersByUserId.get(req.session.userId) || [];
  const idx = list.findIndex((order) => order.id === orderId);

  if (idx === -1) {
    return sendError(res, 404, "Not Found", "Order not found");
  }

  list.splice(idx, 1);
  db.ordersByUserId.set(req.session.userId, list);

  return res.status(204).send();
});

app.get("/admin/metrics", requireAuth, requireAdmin, (req, res) => {
  const users = db.usersByEmail.size;
  const sessions = db.sessionsByToken.size;

  let orders = 0;
  for (const list of db.ordersByUserId.values()) {
    orders += list.length;
  }

  return res.status(200).json({
    message: "OK",
    metrics: { users, sessions, orders },
    ts: nowIso(),
    requestId: res.locals.requestId,
  });
});

app.get("/moved-permanently", (req, res) => {
  res.setHeader("Location", "/ping");
  return res.status(301).end();
});

app.get("/found", (req, res) => {
  res.setHeader("Location", "/ping");
  return res.status(302).end();
});

const CACHE_ETAG = '"rock-shop-etag-v1"';
const CACHE_BODY = { message: "Fresh content", ts: null };

app.get("/cache", (req, res) => {
  const inm = req.headers["if-none-match"];
  const force304 = String(req.query.fresh ?? "") === "0";

  res.setHeader("ETag", CACHE_ETAG);
  res.setHeader("Cache-Control", "private, max-age=0, must-revalidate");

  if (force304 || (inm && String(inm).trim() === CACHE_ETAG)) {
    return res.status(304).end();
  }

  CACHE_BODY.ts = nowIso();
  return res.status(200).json(CACHE_BODY);
});

app.get("/error", (req, res) => {
  return sendError(res, 500, "Internal Server Error", "Something went wrong on the server");
});

app.get("/bad-gateway", (req, res) => {
  return sendError(res, 502, "Bad Gateway", "Upstream service returned invalid response");
});

app.get("/unavailable", (req, res) => {
  res.setHeader("Retry-After", "60");
  return sendError(
    res,
    503,
    "Service Unavailable",
    "Service is temporarily unavailable"
  );
});

app.get("/gateway-timeout", async (req, res) => {
  const wait = Number(req.query.wait ?? 6000);
  const ms = Number.isFinite(wait) ? Math.max(0, wait) : 6000;

  await sleep(ms);

  if (ms >= 5000) {
    return sendError(res, 504, "Gateway Timeout", `Upstream timed out after ${ms}ms`);
  }

  return res.status(200).json({
    message: `OK after ${ms}ms`,
    ts: nowIso(),
    requestId: res.locals.requestId,
  });
});

app.use((req, res) => {
  return sendError(res, 404, "Not Found", "Route does not exist", { path: req.path });
});

app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  return sendError(res, 500, "Internal Server Error", "Unhandled server error");
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Rock Star Shop Mock API running on port ${PORT}`);
  console.log(`Version: ${APP_VERSION}`);
  console.log(`Health: GET /health`);
  console.log(`Reset: POST /__reset`);
  console.log(`Config: POST /__config`);
  console.log(`Admin login: admin@rock.shop / admin123`);
});