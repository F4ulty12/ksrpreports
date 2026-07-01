export default {
  async fetch(request, env) {
    const url = new URL(request.url);
 
    if (request.method === "OPTIONS") {
      return withCors(new Response(null, { status: 204 }));
    }
 
    if (url.pathname === "/submit-report" && request.method === "POST") {
      try {
        return withCors(await handleSubmit(request, env));
      } catch (err) {
        return withCors(json({ error: "Server error", detail: String(err) }, 500));
      }
    }
 
    if (url.pathname === "/interactions" && request.method === "POST") {
      return handleInteraction(request, env);
    }
 
    return new Response("Not found", { status: 404 });
  }
};
 
// ---------- /submit-report ----------
 
async function handleSubmit(request, env) {
  const form = await request.formData();
 
  const who = (form.get("who") || "").toString().trim();
  const role = (form.get("role") || "").toString().trim() || "Not specified";
  const reason = (form.get("reason") || "").toString().trim();
  const evidence = (form.get("evidence") || "").toString().trim();
  const files = form.getAll("images").filter((f) => f instanceof File && f.size > 0).slice(0, 5);
 
  if (!who || !reason) {
    return json({ error: "Missing required fields" }, 400);
  }
 
  const reportId = crypto.randomUUID().slice(0, 8);
 
  const embed = {
    title: "🔒 Anonymous Private Report",
    color: 0xef4444,
    fields: [
      { name: "Reporting", value: who, inline: true },
      { name: "Their Role", value: role, inline: true },
      { name: "What Happened", value: reason.slice(0, 1024) }
    ],
    footer: { text: `Report #${reportId} · Submitted anonymously · Unclaimed` },
    timestamp: new Date().toISOString()
  };
 
  if (evidence) {
    embed.fields.push({ name: "Evidence Link", value: evidence });
  }
 
  const payload = {
    embeds: [embed],
    components: [
      {
        type: 1,
        components: [
          {
            type: 2,
            style: 4, // red / danger
            label: "🚩 Claim Report",
            custom_id: `claim:${reportId}`
          }
        ]
      }
    ]
  };
 
  if (files.length > 0) {
    embed.image = { url: `attachment://${sanitizeName(files[0].name, 0)}` };
    payload.attachments = files.map((f, i) => ({ id: i, filename: sanitizeName(f.name, i) }));
  }
 
  const multipart = new FormData();
  multipart.append("payload_json", JSON.stringify(payload));
  files.forEach((f, i) => multipart.append(`files[${i}]`, f, sanitizeName(f.name, i)));
 
  const postRes = await fetch(
    `https://discord.com/api/v10/channels/${env.CHANNEL_ID}/messages`,
    {
      method: "POST",
      headers: { Authorization: `Bot ${env.BOT_TOKEN}` },
      body: multipart
    }
  );
 
  if (!postRes.ok) {
    const detail = await postRes.text();
    return json({ error: "Discord rejected the report", detail }, 502);
  }
 
  const message = await postRes.json();
 
  // Create a thread on the report message for staff discussion
  await fetch(
    `https://discord.com/api/v10/channels/${env.CHANNEL_ID}/messages/${message.id}/threads`,
    {
      method: "POST",
      headers: {
        Authorization: `Bot ${env.BOT_TOKEN}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        name: `Report #${reportId}`,
        auto_archive_duration: 1440
      })
    }
  );
 
  // Remember the message location in case you ever need to look it up by reportId
  await env.CLAIMS.put(
    `msg:${reportId}`,
    JSON.stringify({ channel_id: message.channel_id, message_id: message.id }),
    { expirationTtl: 60 * 60 * 24 * 180 } // 180 days
  );
 
  return json({ ok: true, reportId });
}
 
function sanitizeName(name, i) {
  const clean = (name || `image${i}.png`).replace(/[^a-zA-Z0-9_.-]/g, "_");
  return clean.length ? clean : `image${i}.png`;
}
 
// ---------- /interactions ----------
 
async function handleInteraction(request, env) {
  const signature = request.headers.get("X-Signature-Ed25519");
  const timestamp = request.headers.get("X-Signature-Timestamp");
  const rawBody = await request.text();
 
  const valid = await verifySignature(rawBody, signature, timestamp, env.PUBLIC_KEY);
  if (!valid) {
    return new Response("Invalid request signature", { status: 401 });
  }
 
  const interaction = JSON.parse(rawBody);
 
  // Discord's verification PING
  if (interaction.type === 1) {
    return json({ type: 1 });
  }
 
  // Button click
  if (interaction.type === 3 && interaction.data?.custom_id?.startsWith("claim:")) {
    const reportId = interaction.data.custom_id.split(":")[1];
    const claimKey = `claim:${reportId}`;
 
    const existingRaw = await env.CLAIMS.get(claimKey);
    if (existingRaw) {
      const existing = JSON.parse(existingRaw);
      return json({
        type: 4, // CHANNEL_MESSAGE_WITH_SOURCE
        data: {
          flags: 64, // ephemeral — only the clicker sees this
          content: `This report is already claimed by **${existing.username}**.`
        }
      });
    }
 
    const user = interaction.member?.user || interaction.user;
    const claimer = {
      username: user.global_name || user.username,
      id: user.id,
      at: new Date().toISOString()
    };
    await env.CLAIMS.put(claimKey, JSON.stringify(claimer));
 
    const message = interaction.message;
    const embed = message.embeds?.[0] || {};
    embed.footer = { text: `Report #${reportId} · Claimed by ${claimer.username}` };
    embed.color = 0x22c55e; // green
 
    return json({
      type: 7, // UPDATE_MESSAGE — edits the original message in place
      data: {
        embeds: [embed],
        components: [
          {
            type: 1,
            components: [
              {
                type: 2,
                style: 3, // green / success
                label: `✅ Claimed by ${claimer.username}`,
                custom_id: `claim:${reportId}`,
                disabled: true
              }
            ]
          }
        ]
      }
    });
  }
 
  return json({
    type: 4,
    data: { flags: 64, content: "Unknown interaction." }
  });
}
 
async function verifySignature(body, signature, timestamp, publicKeyHex) {
  if (!signature || !timestamp || !publicKeyHex) return false;
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      hexToBytes(publicKeyHex),
      { name: "Ed25519" },
      false,
      ["verify"]
    );
    const sig = hexToBytes(signature);
    const data = new TextEncoder().encode(timestamp + body);
    return await crypto.subtle.verify("Ed25519", key, sig, data);
  } catch (e) {
    return false;
  }
}
 
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}
 
// ---------- helpers ----------
 
function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}
 
function withCors(res) {
  res.headers.set("Access-Control-Allow-Origin", "*");
  res.headers.set("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.headers.set("Access-Control-Allow-Headers", "Content-Type");
  return res;
}
