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

function validateTenant(req) {
  const header = req.headers["x-ms-client-principal"];
  if (!header) return false;
  const principal = JSON.parse(Buffer.from(header, "base64").toString("utf8"));
  const tenantClaim = (principal.claims || []).find(
    c => c.typ === "http://schemas.microsoft.com/identity/claims/tenantid"
  );
  return tenantClaim && tenantClaim.val === process.env.AZURE_TENANT_ID;
}

module.exports = async function (context, req) {
  if (!validateTenant(req)) {
    context.res = { status: 403, headers: { "Content-Type": "application/json" }, body: { error: "Access denied: tenant not allowed" } };
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

    const id = context.bindingData.id;
    const client = new TableClient(url, "TimeEntries", cred);
    await client.deleteEntity("demo", id);
    context.res = { status: 200, headers: { "Content-Type": "application/json" }, body: { deleted: id } };
  } catch (err) {
    if (err.statusCode === 404) {
      context.res = { status: 404, headers: { "Content-Type": "application/json" }, body: { error: "Not found" } };
    } else {
      context.log("DELETE error:", err.message);
      context.res = { status: 500, headers: { "Content-Type": "application/json" }, body: { error: err.message } };
    }
  }
};
