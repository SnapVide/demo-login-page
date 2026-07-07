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

    const username = String(body.username || "").trim();
    const password = String(body.password || "");

    if (!username || !password) {
      return Response.json(
        { ok: false, error: "Missing username or password." },
        { status: 400 }
      );
    }

    const salt = randomBase64(16);
    const passwordHash = await hashSecret(password, salt);

    const result = await env.DB.prepare(
      "INSERT INTO login_attempts (username, password_hash, password_salt) VALUES (?, ?, ?) RETURNING id"
    )
      .bind(username, passwordHash, salt)
      .first();

    return Response.json({
      ok: true,
      loginAttemptId: result.id
    });
  } catch (error) {
    return Response.json(
      { ok: false, error: "Server error." },
      { status: 500 }
    );
  }
}