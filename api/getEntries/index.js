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

// Validate that the caller authenticated through our Entra ID provider.
// The built-in AAD provider sets identityProvider to 'aad'. Since the
// provider is configured with a single-tenant issuer URL, only users
// from the expected tenant can obtain a valid session.
function validateAuth(req) {
  const header = req.headers["x-ms-client-principal"];
  if (!header) return false;
  const principal = JSON.parse(Buffer.from(header, "base64").toString("utf8"));
  return principal.identityProvider === "aad";
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

    const client = new TableClient(url, "TimeEntries", cred);
    const entries = [];
    for await (const entity of client.listEntities({ queryOptions: { filter: "PartitionKey eq 'demo'" } })) {
      entries.push({
        id: entity.rowKey,
        date: entity.date,
        project: entity.project,
        task: entity.task,
        hours: entity.hours,
        billable: entity.billable,
        notes: entity.notes || ""
      });
    }
    entries.sort((a, b) => (b.date > a.date ? 1 : b.date < a.date ? -1 : 0));
    context.res = { status: 200, headers: { "Content-Type": "application/json" }, body: entries };
  } catch (err) {
    context.log("GET error:", err.message);
    context.res = { status: 500, headers: { "Content-Type": "application/json" }, body: { error: err.message } };
  }
};
