const db = require('./database');

db.serialize(() => {
    const defaultUsers = [
        { id: "USR01", name: "Herrera, Christopher John", username: "admin", password: "admin123", role: "admin", status: "Active" },
        { id: "USR02", name: "Teresita, Tragura", username: "staff", password: "staff123", role: "staff", status: "Active" }
    ];

    const stmt = db.prepare("INSERT INTO users VALUES (?,?,?,?,?,?)");
    defaultUsers.forEach(u => stmt.run(u.id, u.name, u.username, u.password, u.role, u.status));
    stmt.finalize();

    console.log("Database seeded successfully.");
});
db.close();
