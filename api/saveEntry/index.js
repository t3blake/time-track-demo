if (!globalThis.crypto) { globalThis.crypto = require("crypto").webcrypto; }

const { TableClient, TableServiceClient } = require("@azure/data-tables");
const { ClientCertificateCredential } = require("@azure/identity");

function getCred() {
  const pem = Buffer.from(process.env.AZURE_CLIENT_CERTIFICATE, "base64").toString("utf8");
  return new ClientCertificateCredential(
    process.env.AZURE_TENANT_ID,
    process.env.AZURE_CLIENT_ID,
    { certificate: pem }
  );
}

// Validate that the caller authenticated through our custom OIDC provider.
// The provider is configured with a single-tenant issuer URL, so only users
// from the expected tenant can obtain a valid session.
function validateAuth(req) {
  const header = req.headers["x-ms-client-principal"];
  if (!header) return false;
  const principal = JSON.parse(Buffer.from(header, "base64").toString("utf8"));
  return principal.identityProvider === "entra";
}

module.exports = async function (context, req) {
  if (!validateAuth(req)) {
    context.res = { status: 403, headers: { "Content-Type": "application/json" }, body: { error: "Access denied" } };
    return;
  }
  const url = process.env.TABLE_STORAGE_URL;
  if (!url) {
    context.res = { status: 500, headers: { "Content-Type": "application/json" }, body: { error: "TABLE_STORAGE_URL not configured" } };
    return;
  }
  try {
    const cred = getCred();
    const svc = new TableServiceClient(url, cred);
    try { await svc.createTable("TimeEntries"); } catch (e) { if (e.statusCode !== 409 && e.statusCode !== 403) throw e; }

    const body = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
    const id = body.id || Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
    const entity = {
      partitionKey: "demo", rowKey: id,
      date: String(body.date),
      project: String(body.project),
      task: String(body.task),
      hours: Number(body.hours),
      billable: Boolean(body.billable),
      notes: String(body.notes || "")
    };

    const client = new TableClient(url, "TimeEntries", cred);
    await client.upsertEntity(entity, "Replace");
    context.res = {
      status: 200,
      headers: { "Content-Type": "application/json" },
      body: { id, date: entity.date, project: entity.project, task: entity.task, hours: entity.hours, billable: entity.billable, notes: entity.notes }
    };
  } catch (err) {
    context.log("POST error:", err.message);
    context.res = { status: 500, headers: { "Content-Type": "application/json" }, body: { error: err.message } };
  }
};
