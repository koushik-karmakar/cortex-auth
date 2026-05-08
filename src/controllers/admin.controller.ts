import type { Request, Response } from "express";
import { db } from "../db/db.js";
import { oauthClients } from "../db/schema.js";
import crypto from "node:crypto";
import { v4 as uuidv4 } from "uuid";
import { eq } from "drizzle-orm";

class Admin_controller {
  admin(req: Request, res: Response) {
    const admin = req.adminUser!;
    res.status(200).send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Admin · Cortex</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:system-ui,sans-serif;background:#f4f4f6;min-height:100vh}
    nav{background:#1a1a2e;padding:.875rem 2rem;display:flex;align-items:center;
        justify-content:space-between}
    .nav-brand{color:#b0a8f8;font-weight:700;font-size:1.1rem;letter-spacing:.5px}
    .nav-user{display:flex;align-items:center;gap:.75rem}
    .nav-user img{width:32px;height:32px;border-radius:50%;object-fit:cover;
                  border:2px solid #7f77dd}
    .nav-user span{color:#ccc;font-size:13px}
    .nav-user a{color:#b0a8f8;font-size:13px;text-decoration:none;
                padding:4px 12px;border:1px solid #7f77dd;border-radius:6px;
                transition:background .15s}
    .nav-user a:hover{background:#7f77dd;color:#fff}
    main{max-width:1000px;margin:0 auto;padding:2rem 1.5rem}
    h1{font-size:1.4rem;font-weight:600;color:#1a1a1a;margin-bottom:1.5rem}
    .card{background:#fff;border-radius:12px;padding:1.5rem;
          border:1px solid #e0e0e4;margin-bottom:1.5rem}
    h2{font-size:.95rem;font-weight:600;margin-bottom:1rem;color:#1a1a1a}
    label{display:block;font-size:12px;color:#666;margin-bottom:4px;margin-top:.75rem}
    label:first-of-type{margin-top:0}
    input,textarea{width:100%;padding:.65rem 1rem;border:1.5px solid #e0e0e4;
      border-radius:8px;font-size:14px;font-family:inherit;transition:border-color .15s}
    input:focus,textarea:focus{outline:none;border-color:#7f77dd}
    .btn{padding:.65rem 1.25rem;border-radius:8px;border:none;
         font-size:14px;font-weight:600;cursor:pointer;transition:opacity .15s}
    .btn:hover{opacity:.85}
    .btn-primary{background:#7f77dd;color:#fff;margin-top:1rem}
    .btn-danger{background:#fee2e2;color:#dc2626;padding:4px 12px;
                font-size:12px;font-weight:500}
    table{width:100%;border-collapse:collapse;font-size:13px}
    th{text-align:left;padding:.5rem .75rem;border-bottom:2px solid #e0e0e4;
       color:#666;font-weight:500;white-space:nowrap}
    td{padding:.65rem .75rem;border-bottom:1px solid #f0f0f4;vertical-align:top}
    .mono{font-family:monospace;background:#f4f4f6;padding:2px 6px;
          border-radius:4px;font-size:11px;word-break:break-all}
    .badge{display:inline-block;padding:2px 8px;border-radius:20px;
           font-size:11px;background:#ede9fe;color:#7f77dd;margin:1px}
    .empty{color:#999;text-align:center;padding:2rem;font-size:14px}
    /* Modal */
    .overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.45);
             z-index:50;align-items:center;justify-content:center}
    .overlay.open{display:flex}
    .modal{background:#fff;border-radius:16px;padding:2rem;
           max-width:500px;width:90%;box-shadow:0 8px 40px rgba(0,0,0,.2)}
    .modal h3{font-size:1rem;font-weight:600;margin-bottom:.5rem;color:#1a1a1a}
    .modal .warn{font-size:12px;color:#dc2626;margin-bottom:1rem}
    .cred-row{margin-bottom:1rem}
    .cred-label{font-size:11px;color:#666;margin-bottom:4px}
    .cred-val{font-family:monospace;background:#f4f4f6;padding:.5rem .75rem;
              border-radius:8px;font-size:13px;word-break:break-all;
              border:1px solid #e0e0e4;position:relative}
    .copy-btn{float:right;background:none;border:none;cursor:pointer;
              color:#7f77dd;font-size:12px;font-weight:600}
    .toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);
           background:#1a1a1a;color:#fff;padding:10px 20px;border-radius:10px;
           font-size:13px;display:none;z-index:100;white-space:nowrap}
    .toast.show{display:block}
  </style>
</head>
<body>
<nav>
  <span class="nav-brand"> Cortex Admin</span>
  <div class="nav-user">
    ${admin.picture ? `<img src="${admin.picture}" alt="${admin.name}" />` : ""}
    <span>${admin.name}</span>
    <a href="/auth/admin/logout">Logout</a>
  </div>
</nav>

<main>
  <h1>OAuth Clients</h1>

  <div class="card">
    <h2>Create New Client</h2>
    <label>App Name</label>
    <input id="f-name" placeholder="e.g. Checkbox App" />
    <label>Redirect URIs <span style="color:#999">(one per line)</span></label>
    <textarea id="f-uris" rows="3"
      placeholder="https://myapp.com/auth/callback&#10;http://localhost:3000/auth/callback"></textarea>
    <label>Scopes <span style="color:#999">(space separated)</span></label>
    <input id="f-scopes" value="openid profile email" />
    <button class="btn btn-primary" onclick="createClient()">
      Create Client
    </button>
  </div>

  <div class="card">
    <h2>Registered Clients</h2>
    <div id="clients-wrap">
      <p class="empty">Loading…</p>
    </div>
  </div>
</main>

<!-- Credentials modal -->
<div class="overlay" id="cred-modal">
  <div class="modal">
    <h3> Client Created — Save These Credentials</h3>
    <p class="warn"> The client secret is shown only once. Copy it now.</p>
    <div class="cred-row">
      <div class="cred-label">Client ID</div>
      <div class="cred-val" id="m-client-id">
        <button class="copy-btn" onclick="copy('m-client-id')">Copy</button>
        <span></span>
      </div>
    </div>
    <div class="cred-row">
      <div class="cred-label">Client Secret</div>
      <div class="cred-val" id="m-client-secret">
        <button class="copy-btn" onclick="copy('m-client-secret')">Copy</button>
        <span></span>
      </div>
    </div>
    <button class="btn btn-primary" style="width:100%"
            onclick="closeModal()">
      I've saved these → Close
    </button>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
function toast(msg, duration = 2500) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.classList.add("show");
  setTimeout(() => t.classList.remove("show"), duration);
}

function copy(elId) {
  const text = document.querySelector("#" + elId + " span").textContent;
  navigator.clipboard.writeText(text).then(() => toast("Copied!"));
}

function closeModal() {
  document.getElementById("cred-modal").classList.remove("open");
}

async function loadClients() {
  const res = await fetch("/admin/api/clients");
  if (!res.ok) { window.location = "/auth/admin/login"; return; }
  const clients = await res.json();
  const wrap = document.getElementById("clients-wrap");
  if (!clients.length) {
    wrap.innerHTML = '<p class="empty">No clients yet. Create one above.</p>';
    return;
  }
  wrap.innerHTML = \`<table>
    <thead>
      <tr>
        <th>Name</th><th>Client ID</th>
        <th>Redirect URIs</th><th>Scopes</th><th></th>
      </tr>
    </thead>
    <tbody>
      \${clients.map(c => \`
        <tr>
          <td><strong>\${esc(c.name)}</strong></td>
          <td><span class="mono">\${esc(c.clientId)}</span></td>
          <td style="font-size:12px">
            \${c.redirectUris.map(u => \`<div>\${esc(u)}</div>\`).join("")}
          </td>
          <td>\${c.scopes.map(s =>
            \`<span class="badge">\${esc(s)}</span>\`).join("")}
          </td>
          <td>
            <button class="btn btn-danger"
              onclick="deleteClient('\${esc(c.clientId)}')">
              Delete
            </button>
          </td>
        </tr>\`).join("")}
    </tbody>
  </table>\`;
}

function esc(str) {
  return String(str)
    .replace(/&/g,"&amp;").replace(/</g,"&lt;")
    .replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

async function createClient() {
  const name  = document.getElementById("f-name").value.trim();
  const uris  = document.getElementById("f-uris").value
                  .split("\\n").map(s=>s.trim()).filter(Boolean);
  const scopes = document.getElementById("f-scopes").value
                   .trim().split(/\\s+/).filter(Boolean);
  if (!name || !uris.length) {
    toast("Name and at least one redirect URI are required"); return;
  }
  const res = await fetch("/admin/api/clients", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, redirectUris: uris, scopes }),
  });
  const data = await res.json();
  if (!res.ok) { toast("Error: " + JSON.stringify(data)); return; }

  document.querySelector("#m-client-id span").textContent   = data.clientId;
  document.querySelector("#m-client-secret span").textContent = data.clientSecret;
  document.getElementById("cred-modal").classList.add("open");
  document.getElementById("f-name").value = "";
  document.getElementById("f-uris").value = "";
  loadClients();
}

async function createClient() {
  const name  = document.getElementById("f-name").value.trim();
  const uris  = document.getElementById("f-uris").value
                  .split("\\n").map(s=>s.trim()).filter(Boolean);
  const scopes = document.getElementById("f-scopes").value
                   .trim().split(/\\s+/).filter(Boolean);
  if (!name || !uris.length) {
    toast("Name and at least one redirect URI are required"); return;
  }
  const res = await fetch("/admin/api/clients", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, redirectUris: uris, scopes }),
  });
  const data = await res.json();
  if (!res.ok) { toast("Error: " + JSON.stringify(data)); return; }

  document.querySelector("#m-client-id span").textContent    = data.clientId;
  document.querySelector("#m-client-secret span").textContent = data.clientSecret;
  document.getElementById("cred-modal").classList.add("open");
  document.getElementById("f-name").value = "";
  document.getElementById("f-uris").value = "";

  await loadClients(); 
}

async function deleteClient(clientId) {
  if (!confirm("Delete client " + clientId + "?")) return;

  const rows = document.querySelectorAll("tbody tr");
  for (const row of rows) {
    if (row.textContent.includes(clientId)) {
      row.style.opacity = "0.4";
      row.style.pointerEvents = "none";
    }
  }

  const res = await fetch("/admin/api/clients/" + clientId, {
    method: "DELETE",
  });

  if (!res.ok) {
    toast("Delete failed — please try again");
    await loadClients(); 
    return;
  }

  toast("Client deleted");
  await loadClients();
}

loadClients();
</script>
</body>
</html>`);
  }

  async adminGetAplication(_req: Request, res: Response) {
    const clients = await db
      .select({
        id: oauthClients.id,
        name: oauthClients.name,
        clientId: oauthClients.clientId,
        redirectUris: oauthClients.redirectUris,
        scopes: oauthClients.scopes,
        createdAt: oauthClients.createdAt,
      })
      .from(oauthClients);
    res.status(200).json(clients);
  }

  async adminPostAplication(req: Request, res: Response) {
    const { name, redirectUris, scopes } = req.body as {
      name: string;
      redirectUris: string[];
      scopes?: string[];
    };
    if (!name || !redirectUris?.length) {
      res.status(400).json({ error: "name and redirectUris are required" });
      return;
    }
    const clientId = `cortex_${crypto.randomBytes(16).toString("hex")}`;
    const clientSecret = crypto.randomBytes(32).toString("base64url");
    await db.insert(oauthClients).values({
      id: uuidv4(),
      name,
      clientId,
      clientSecret,
      redirectUris,
      scopes: scopes ?? ["openid", "profile", "email"],
    });
    res.status(201).json({ clientId, clientSecret, name });
  }

  async adminDeleteAplication(req: Request, res: Response) {
    try {
      const { clientId } = req.params as { clientId: string };
      if (!clientId) {
        res.status(400).json({ error: "Missing clientId" });
        return;
      }
      const [existing] = await db
        .select({ id: oauthClients.id })
        .from(oauthClients)
        .where(eq(oauthClients.clientId, clientId))
        .limit(1);

      if (!existing) {
        res.status(404).json({ error: "Client not found" });
        return;
      }

      await db.delete(oauthClients).where(eq(oauthClients.clientId, clientId));

      res.status(200).json({ ok: true });
    } catch (err) {
      console.error("Delete client error:", err);
      res.status(500).json({ error: "Failed to delete client" });
    }
  }
}

export const adminController = new Admin_controller();
