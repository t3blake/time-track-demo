if (!globalThis.crypto) { globalThis.crypto = require("crypto").webcrypto; }

const { TableClient, TableServiceClient } = require("@azure/data-tables");
const { ClientSecretCredential } = require("@azure/identity");

function getCred() {
  return new ClientSecretCredential(
    process.env.AZURE_TENANT_ID,
    process.env.AZURE_CLIENT_ID,
    process.env.AZURE_CLIENT_SECRET
  );
}

module.exports = async function (context, req) {
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
