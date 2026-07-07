function randomBase64(bytes = 16) {
  const array = new Uint8Array(bytes);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...array));
}

async function hashSecret(secret, saltBase64) {
  const encoder = new TextEncoder();

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const salt = Uint8Array.from(atob(saltBase64), c => c.charCodeAt(0));

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: 100000,
      hash: "SHA-256"
    },
    key,
    256
  );

  return btoa(String.fromCharCode(...new Uint8Array(bits)));
}

export async function onRequestPost({ request, env }) {
  try {
    const body = await request.json();

    const loginAttemptId = body.loginAttemptId || null;
    const username = String(body.username || "").trim();
    const code = String(body.code || "").trim();

    if (!/^\d{4}$/.test(code)) {
      return Response.json(
        { ok: false, error: "Invalid code." },
        { status: 400 }
      );
    }

    const salt = randomBase64(16);
    const codeHash = await hashSecret(code, salt);

    await env.DB.prepare(
      "INSERT INTO code_attempts (login_attempt_id, username, code, code) VALUES (?, ?, ?, ?)"
    )
      .bind(loginAttemptId, username, codeHash, salt)
      .run();

    return Response.json({ ok: true });
  } catch (error) {
    return Response.json(
      { ok: false, error: "Server error." },
      { status: 500 }
    );
  }
}