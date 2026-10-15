// Runs only when the MongoDB data volume is first initialized.
for (const [database, username, password] of [
  ["users", "users_service", process.env.USERS_MONGO_PASSWORD],
  ["vpn_configs", "vpn_configs_service", process.env.VPN_CONFIGS_MONGO_PASSWORD],
]) {
  if (!password) throw new Error("Service database password is required");
  db.getSiblingDB(database).createUser({
    user: username,
    pwd: password,
    roles: [{ role: "readWrite", db: database }],
  });
}
