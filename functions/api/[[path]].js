import { memberData } from "../../lib/member.js";

const encoder = new TextEncoder();
const PASSWORD_ITERATIONS = 100000;
const SESSION_DURATION_MS = 7 * 24 * 60 * 60 * 1000;
const LOGIN_BLOCK_DURATION_MS = 15 * 60 * 1000;

/* -------------------------------------------------------
   Antworten
------------------------------------------------------- */

function json(value, status = 200, headers = {}) {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...headers
    }
  });
}

function errorResponse(message, status = 400) {
  return json({ error: message }, status);
}

/* -------------------------------------------------------
   Kryptografie
------------------------------------------------------- */

function bytesToHex(bytes) {
  return Array.from(bytes, byte =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

async function sha256(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(value)
  );

  return bytesToHex(new Uint8Array(digest));
}

function randomHex(byteLength) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

async function hashPassword(password, salt) {
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: encoder.encode(salt),
      iterations: PASSWORD_ITERATIONS,
      hash: "SHA-256"
    },
    passwordKey,
    256
  );

  return bytesToHex(new Uint8Array(derivedBits));
}

function constantTimeEqual(valueA, valueB) {
  if (typeof valueA !== "string" || typeof valueB !== "string") {
    return false;
  }

  const bytesA = encoder.encode(valueA);
  const bytesB = encoder.encode(valueB);

  let difference = bytesA.length ^ bytesB.length;
  const maximumLength = Math.max(bytesA.length, bytesB.length);

  for (let index = 0; index < maximumLength; index++) {
    difference |=
      (bytesA[index] || 0) ^
      (bytesB[index] || 0);
  }

  return difference === 0;
}

/* -------------------------------------------------------
   Cookies und Sitzungen
------------------------------------------------------- */

function getCookie(name, request) {
  const cookieHeader = request.headers.get("Cookie") || "";

  const cookiePart = cookieHeader
    .split(";")
    .map(part => part.trim())
    .find(part => part.startsWith(`${name}=`));

  return cookiePart
    ? cookiePart.slice(name.length + 1)
    : "";
}

function createSessionCookie(token, maxAge) {
  return [
    `sk_session=${token}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${maxAge}`
  ].join("; ");
}

async function getSession(context) {
  const token = getCookie("sk_session", context.request);

  if (!/^[0-9a-f]{64}$/.test(token)) {
    return null;
  }

  const tokenHash = await sha256(token);

  return context.env.DB
    .prepare(
      "SELECT username, role FROM sessions " +
      "WHERE token_hash = ? AND expires_at > ?"
    )
    .bind(tokenHash, Date.now())
    .first();
}

/* -------------------------------------------------------
   Hilfsfunktionen
------------------------------------------------------- */

async function readRequestBody(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

function isRequestOriginValid(request) {
  const origin = request.headers.get("Origin");

  if (!origin) {
    return true;
  }

  return origin === new URL(request.url).origin;
}

function isValidUsername(username) {
  return /^[A-Za-z0-9._-]{3,32}$/.test(username);
}

function getChangedRows(result) {
  const changes = result?.meta?.changes;

  if (typeof changes === "number") {
    return changes;
  }

  return 0;
}

/* -------------------------------------------------------
   Standardbenutzer
------------------------------------------------------- */

async function bootstrapDefaultUser(environment) {
  if (!environment.DEFAULT_USER_PASSWORD) {
    return;
  }

  const setting = await environment.DB
    .prepare(
      "SELECT value FROM settings " +
      "WHERE key = 'default_user_initialized'"
    )
    .first();

  if (setting) {
    return;
  }

  const salt = randomHex(16);
  const passwordHash = await hashPassword(
    environment.DEFAULT_USER_PASSWORD,
    salt
  );

  await environment.DB.batch([
    environment.DB
      .prepare(
        "INSERT OR IGNORE INTO users " +
        "(username, salt, password_hash, created_at) " +
        "VALUES (?, ?, ?, ?)"
      )
      .bind(
        "seelenkraft",
        salt,
        passwordHash,
        Date.now()
      ),

    environment.DB
      .prepare(
        "INSERT OR IGNORE INTO settings (key, value) " +
        "VALUES ('default_user_initialized', '1')"
      )
  ]);
}

/* -------------------------------------------------------
   Anmeldung
------------------------------------------------------- */

async function login(context) {
  const environment = context.env;

  if (!environment.DB || !environment.ADMIN_PASSWORD) {
    return errorResponse(
      "Server ist noch nicht eingerichtet. " +
      "D1 und ADMIN_PASSWORD konfigurieren.",
      503
    );
  }

  const requestBody = await readRequestBody(context.request);
  const username = String(requestBody.username || "").trim();
  const password = String(requestBody.password || "");

  if (
    !isValidUsername(username) ||
    !password ||
    password.length > 128
  ) {
    return errorResponse(
      "Ungültige Zugangsdaten.",
      401
    );
  }

  const ipAddress =
    context.request.headers.get("CF-Connecting-IP") ||
    "unknown";

  const loginAttemptKey = await sha256(
    `${ipAddress}|${username.toLowerCase()}`
  );

  const now = Date.now();

  const previousAttempt = await environment.DB
    .prepare(
      "SELECT failures, expires_at " +
      "FROM login_attempts WHERE key = ?"
    )
    .bind(loginAttemptKey)
    .first();

  if (
    previousAttempt &&
    previousAttempt.expires_at > now &&
    previousAttempt.failures >= 5
  ) {
    return errorResponse(
      "Zu viele Versuche. Bitte später erneut anmelden.",
      429
    );
  }

  await bootstrapDefaultUser(environment);

  let role = null;

  if (
    username.toLowerCase() === "admin" &&
    constantTimeEqual(
      password,
      environment.ADMIN_PASSWORD
    )
  ) {
    role = "admin";
  } else if (username.toLowerCase() !== "admin") {
    const user = await environment.DB
      .prepare(
        "SELECT username, salt, password_hash " +
        "FROM users WHERE username = ?"
      )
      .bind(username)
      .first();

    if (user) {
      const suppliedPasswordHash = await hashPassword(
        password,
        user.salt
      );

      if (
        constantTimeEqual(
          suppliedPasswordHash,
          user.password_hash
        )
      ) {
        role = "member";
      }
    }
  }

  if (!role) {
    await environment.DB
      .prepare(
        "INSERT INTO login_attempts " +
        "(key, failures, expires_at) " +
        "VALUES (?, ?, ?) " +
        "ON CONFLICT(key) DO UPDATE SET " +
        "failures = CASE " +
        "WHEN expires_at < ? THEN 1 " +
        "ELSE failures + 1 END, " +
        "expires_at = ?"
      )
      .bind(
        loginAttemptKey,
        1,
        now + LOGIN_BLOCK_DURATION_MS,
        now,
        now + LOGIN_BLOCK_DURATION_MS
      )
      .run();

    return errorResponse(
      "Anmeldung fehlgeschlagen. Bitte Zugangsdaten prüfen.",
      401
    );
  }

  await environment.DB
    .prepare(
      "DELETE FROM login_attempts WHERE key = ?"
    )
    .bind(loginAttemptKey)
    .run();

  const sessionToken = randomHex(32);
  const sessionTokenHash = await sha256(sessionToken);
  const sessionUsername =
    role === "admin" ? "admin" : username;

  await environment.DB
    .prepare(
      "INSERT INTO sessions " +
      "(token_hash, username, role, expires_at) " +
      "VALUES (?, ?, ?, ?)"
    )
    .bind(
      sessionTokenHash,
      sessionUsername,
      role,
      now + SESSION_DURATION_MS
    )
    .run();

  return json(
    {
      ok: true,
      role,
      username: sessionUsername
    },
    200,
    {
      "Set-Cookie": createSessionCookie(
        sessionToken,
        604800
      )
    }
  );
}

/* -------------------------------------------------------
   Benutzerverwaltung
------------------------------------------------------- */

async function handleAdminUsers(context, currentSession) {
  if (!currentSession || currentSession.role !== "admin") {
    return errorResponse(
      "Nur für Administratoren.",
      403
    );
  }

  const database = context.env.DB;
  const method = context.request.method;

  if (method === "GET") {
    const result = await database
      .prepare(
        "SELECT username, created_at " +
        "FROM users ORDER BY username"
      )
      .all();

    return json({
      users: [
        {
          username: "admin",
          created_at: null
        },
        ...(result.results || [])
      ]
    });
  }

  const requestBody = await readRequestBody(
    context.request
  );

  const username = String(
    requestBody.username || ""
  ).trim();

  if (
    !isValidUsername(username) ||
    username.toLowerCase() === "admin"
  ) {
    return errorResponse(
      "Benutzername ungültig oder reserviert."
    );
  }

  if (method === "DELETE") {
    const result = await database
      .prepare(
        "DELETE FROM users WHERE username = ?"
      )
      .bind(username)
      .run();

    if (getChangedRows(result) === 0) {
      return errorResponse(
        "Nutzer nicht gefunden.",
        404
      );
    }

    await database
      .prepare(
        "DELETE FROM sessions WHERE username = ?"
      )
      .bind(username)
      .run();

    return json({ ok: true });
  }

  if (method !== "POST" && method !== "PUT") {
    return errorResponse(
      "Methode nicht erlaubt.",
      405
    );
  }

  const password = String(
    requestBody.password || ""
  );

  if (password.length < 10 || password.length > 128) {
    return errorResponse(
      "Passwort muss 10 bis 128 Zeichen lang sein."
    );
  }

  let salt;
  let passwordHash;

  try {
    salt = randomHex(16);
    passwordHash = await hashPassword(password, salt);
  } catch (cryptoError) {
    console.error(
      "Passwort-Hash konnte nicht erstellt werden:",
      cryptoError
    );

    return errorResponse(
      "Das Passwort konnte nicht sicher verarbeitet werden.",
      500
    );
  }

  if (method === "POST") {
    const existingUser = await database
      .prepare(
        "SELECT username FROM users WHERE username = ?"
      )
      .bind(username)
      .first();

    if (existingUser) {
      return errorResponse(
        "Dieser Benutzername existiert bereits.",
        409
      );
    }

    try {
      await database
        .prepare(
          "INSERT INTO users " +
          "(username, salt, password_hash, created_at) " +
          "VALUES (?, ?, ?, ?)"
        )
        .bind(
          username,
          salt,
          passwordHash,
          Date.now()
        )
        .run();

      return json(
        {
          ok: true,
          username
        },
        201
      );
    } catch (databaseError) {
      console.error(
        "Benutzer konnte nicht angelegt werden:",
        databaseError
      );

      return errorResponse(
        "Der Benutzer konnte nicht gespeichert werden: " +
        String(databaseError?.message || databaseError),
        500
      );
    }
  }

  if (method === "PUT") {
    const result = await database
      .prepare(
        "UPDATE users " +
        "SET salt = ?, password_hash = ? " +
        "WHERE username = ?"
      )
      .bind(
        salt,
        passwordHash,
        username
      )
      .run();

    if (getChangedRows(result) === 0) {
      return errorResponse(
        "Nutzer nicht gefunden.",
        404
      );
    }

    await database
      .prepare(
        "DELETE FROM sessions WHERE username = ?"
      )
      .bind(username)
      .run();

    return json({ ok: true });
  }

  return errorResponse(
    "Methode nicht erlaubt.",
    405
  );
}

/* -------------------------------------------------------
   Haupt-Routing
------------------------------------------------------- */

export async function onRequest(context) {
  const request = context.request;
  const url = new URL(request.url);
  const route = url.pathname.replace(/\/$/, "");

  if (!context.env.DB) {
    return errorResponse(
      "D1-Bindung DB fehlt.",
      503
    );
  }

  if (
    !["GET", "POST", "PUT", "DELETE"].includes(
      request.method
    )
  ) {
    return errorResponse(
      "Methode nicht erlaubt.",
      405
    );
  }

  if (
    request.method !== "GET" &&
    !isRequestOriginValid(request)
  ) {
    return errorResponse(
      "Ungültiger Ursprung.",
      403
    );
  }

  try {
    if (
      route === "/api/login" &&
      request.method === "POST"
    ) {
      return await login(context);
    }

    const currentSession = await getSession(context);

    if (
      route === "/api/me" &&
      request.method === "GET"
    ) {
      if (!currentSession) {
        return json({
          authenticated: false
        });
      }

      return json({
        authenticated: true,
        role: currentSession.role,
        username: currentSession.username
      });
    }

    if (
      route === "/api/logout" &&
      request.method === "POST"
    ) {
      const sessionToken = getCookie(
        "sk_session",
        request
      );

      if (currentSession && sessionToken) {
        await context.env.DB
          .prepare(
            "DELETE FROM sessions " +
            "WHERE token_hash = ?"
          )
          .bind(await sha256(sessionToken))
          .run();
      }

      return json(
        { ok: true },
        200,
        {
          "Set-Cookie": createSessionCookie("", 0)
        }
      );
    }

    if (
      route === "/api/member" &&
      request.method === "GET"
    ) {
      if (!currentSession) {
        return errorResponse(
          "Bitte anmelden.",
          401
        );
      }

      return json({
        ...memberData,
        role: currentSession.role
      });
    }

    if (route === "/api/admin/users") {
      return await handleAdminUsers(
        context,
        currentSession
      );
    }

    return errorResponse(
      "Nicht gefunden.",
      404
    );
  } catch (unexpectedError) {
    console.error(
      "Unerwarteter API-Fehler:",
      unexpectedError
    );

    return errorResponse(
      "Serverfehler: " +
      String(
        unexpectedError?.message ||
        unexpectedError
      ),
      500
    );
  }
}
