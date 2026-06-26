const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');

// Parse CLI arguments
const args = process.argv.slice(2);

if (args.length !== 2) {
    console.log('----------------------------------------------------');
    console.log('❌ ERROR: Invalid arguments.');
    console.log('USAGE: node reset-admin.js <username> <new_password>');
    console.log('EXAMPLE: node reset-admin.js admin "MyNewPass123!"');
    console.log('----------------------------------------------------');
    process.exit(1);
}

const targetUsername = args[0].trim();
const newPassword = args[1].trim();

if (newPassword.length < 4) {
    console.log('❌ ERROR: Password must be at least 4 characters long.');
    process.exit(1);
}

const dbPath = path.resolve(__dirname, 'bhandol.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('❌ ERROR: Could not connect to database:', err.message);
        process.exit(1);
    }
});

console.log(`\n🔍 Searching for user: "${targetUsername}"...`);

db.get(`SELECT id, role FROM users WHERE username = ?`, [targetUsername], async (err, user) => {
    if (err) {
        console.error('❌ ERROR: Database query failed:', err.message);
        db.close();
        process.exit(1);
    }

    if (!user) {
        console.log(`❌ ERROR: User "${targetUsername}" not found in the database.`);
        db.close();
        process.exit(1);
    }

    if (user.role !== 'admin') {
        console.log(`⚠️ WARNING: User "${targetUsername}" is a STAFF member, not an ADMIN.`);
        console.log('Proceeding with password reset anyway...');
    }

    try {
        console.log('🔐 Hashing new password securely...');
        const SALT_ROUNDS = 10;
        const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);

        db.run(`UPDATE users SET password = ? WHERE id = ?`, [hashedPassword, user.id], function (updateErr) {
            if (updateErr) {
                console.error('❌ ERROR: Failed to update password:', updateErr.message);
                db.close();
                process.exit(1);
            }

            console.log('----------------------------------------------------');
            console.log(`✅ SUCCESS! Password for "${targetUsername}" has been reset.`);
            console.log(`You can now log in at the main screen using the new password.`);
            console.log('----------------------------------------------------\n');
            db.close();
            process.exit(0);
        });

    } catch (hashErr) {
        console.error('❌ ERROR: Failed to hash the password properly:', hashErr);
        db.close();
        process.exit(1);
    }
});
