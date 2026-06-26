const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const db = require('./database');

const app = express();
const PORT = 3000;
const SALT_ROUNDS = 10;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '..')));

// =============================================
//  VALIDATION HELPERS
// =============================================
function validateString(val, fieldName, minLen = 1, maxLen = 200) {
    if (typeof val !== 'string' || val.trim().length < minLen) {
        return `${fieldName} is required and must be at least ${minLen} character(s).`;
    }
    if (val.trim().length > maxLen) {
        return `${fieldName} must be at most ${maxLen} characters.`;
    }
    return null;
}

function validateInt(val, fieldName, min = 0, max = 999999) {
    const n = parseInt(val, 10);
    if (isNaN(n) || n < min || n > max) {
        return `${fieldName} must be a number between ${min} and ${max}.`;
    }
    return null;
}

function validationError(res, errors) {
    return res.status(400).json({ error: 'Validation failed', details: errors });
}

// =============================================
//  USERS API
// =============================================
app.get('/api/users', (req, res) => {
    // SECURITY OVERRIDE: User explicitly requested passwords be viewable in Admin portal.
    db.all("SELECT id, name, username, password, role, status FROM users", [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/users', async (req, res) => {
    const { id, name, username, password, role, status } = req.body;

    // Validate inputs
    const errors = [];
    const idErr = validateString(id, 'ID');
    const nameErr = validateString(name, 'Name', 2, 100);
    const usernameErr = validateString(username, 'Username', 3, 50);
    const passwordErr = validateString(password, 'Password', 4, 100);
    const roleErr = validateString(role, 'Role');
    const statusErr = validateString(status, 'Status');
    if (idErr) errors.push(idErr);
    if (nameErr) errors.push(nameErr);
    if (usernameErr) errors.push(usernameErr);
    if (passwordErr) errors.push(passwordErr);
    if (roleErr) errors.push(roleErr);
    if (statusErr) errors.push(statusErr);
    if (!['admin', 'staff'].includes(role)) errors.push('Role must be "admin" or "staff".');
    if (!['Active', 'Inactive'].includes(status)) errors.push('Status must be "Active" or "Inactive".');
    if (errors.length > 0) return validationError(res, errors);

    // SECURITY OVERRIDE: User explicitly requested plaintext passwords.
    const sql = `INSERT INTO users (id, name, username, password, role, status) VALUES (?,?,?,?,?,?)`;
    db.run(sql, [id, name, username, password, role, status], function (err) {
        if (err) {
            if (err.message.includes('UNIQUE')) {
                return res.status(409).json({ error: 'Username already exists.' });
            }
            return res.status(500).json({ error: err.message });
        }
        res.json({ id, name, username, role, status });
    });
});

app.put('/api/users/:id/status', (req, res) => {
    const { status } = req.body;
    if (!['Active', 'Inactive'].includes(status)) {
        return validationError(res, ['Status must be "Active" or "Inactive".']);
    }
    db.run(`UPDATE users SET status = ? WHERE id = ?`, [status, req.params.id], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

app.delete('/api/users/:id', (req, res) => {
    db.run(`DELETE FROM users WHERE id = ?`, [req.params.id], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'User deleted' });
    });
});

app.post('/api/auth/login', (req, res) => {
    let { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Username and password are required.' });
    }

    // Security: Aggressive trimming to remove accidental padding
    username = username.trim();

    // Constant time delay to mitigate brute force & timing attacks
    const failDelay = (callback) => setTimeout(callback, 800 + Math.random() * 400);

    db.get(`SELECT * FROM users WHERE username = ? AND status = 'Active'`, [username], async (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row) {
            // Wait to respond to mask whether the username actually exists (timing attack mitigation)
            return failDelay(() => res.status(401).json({ success: false, message: 'Invalid credentials or inactive account' }));
        }

        try {
            // Support both: legacy bcrypt hashed passwords AND new plain-text passwords
            let isMatch = false;
            if (row.password.startsWith('$2a$') || row.password.startsWith('$2b$')) {
                // bcrypt hash detected from previously created accounts
                isMatch = await bcrypt.compare(password, row.password);
            } else {
                // SECURITY OVERRIDE: Plain-text password (left as plaintext per user request to be viewable)
                isMatch = (password === row.password);
            }

            if (isMatch) {
                res.json({ success: true, user: { id: row.id, name: row.name, username: row.username, role: row.role } });
            } else {
                failDelay(() => res.status(401).json({ success: false, message: 'Invalid credentials or inactive account' }));
            }
        } catch (bcryptErr) {
            failDelay(() => res.status(500).json({ error: 'Authentication error.' }));
        }
    });
});

// =============================================
//  INVENTORY API
// =============================================
app.get('/api/inventory', (req, res) => {
    db.all("SELECT * FROM products", [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/inventory', (req, res) => {
    const { id, name, category, unit, quantity, dateAdded, user } = req.body;

    // Validate — store result to avoid calling validator twice
    const errors = [];
    const idErr = validateString(id, 'ID');
    const nameErr = validateString(name, 'Product Name', 2, 100);
    const catErr = validateString(category, 'Category');
    const unitErr = validateString(unit, 'Unit');
    const qtyErr = validateInt(quantity, 'Quantity', 1);
    const dateErr = validateString(dateAdded, 'Date');
    const userErr = validateString(user, 'User');
    if (idErr) errors.push(idErr);
    if (nameErr) errors.push(nameErr);
    if (catErr) errors.push(catErr);
    if (unitErr) errors.push(unitErr);
    if (qtyErr) errors.push(qtyErr);
    if (dateErr) errors.push(dateErr);
    if (userErr) errors.push(userErr);
    if (errors.length > 0) return validationError(res, errors);

    const sql = `INSERT INTO products (id, name, category, unit, quantity, dateAdded, user) VALUES (?,?,?,?,?,?,?)`;
    db.run(sql, [id, name.trim(), category.trim(), unit.trim(), parseInt(quantity, 10), dateAdded, user], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, id });
    });
});

app.put('/api/inventory/:id', (req, res) => {
    const { name, category, unit, quantity } = req.body;

    const errors = [];
    const nameErr = validateString(name, 'Product Name', 2, 100);
    const catErr = validateString(category, 'Category');
    const unitErr = validateString(unit, 'Unit');
    const qtyErr = validateInt(quantity, 'Quantity', 0);
    if (nameErr) errors.push(nameErr);
    if (catErr) errors.push(catErr);
    if (unitErr) errors.push(unitErr);
    if (qtyErr) errors.push(qtyErr);
    if (errors.length > 0) return validationError(res, errors);

    const sql = `UPDATE products SET name = ?, category = ?, unit = ?, quantity = ? WHERE id = ?`;
    db.run(sql, [name.trim(), category.trim(), unit.trim(), parseInt(quantity, 10), req.params.id], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

app.put('/api/inventory/:id/quantity', (req, res) => {
    const { quantityDelta, user } = req.body;
    // Bug Fix: store result once to avoid redundant double-call
    const deltaErr = validateInt(quantityDelta, 'Quantity Delta', -999999, 999999);
    if (deltaErr) return validationError(res, [deltaErr]);

    const delta = parseInt(quantityDelta, 10);

    // Low Stock Protection — only applies to stock-out (negative delta)
    if (delta < 0) {
        db.get(`SELECT value FROM settings WHERE key = 'lowStockProtectionEnabled'`, [], (err, row) => {
            if (!row || row.value !== 'true') {
                // Protection is disabled — proceed normally
                executeQuantityUpdate();
                return;
            }
            // Protection is enabled — check if the resulting quantity would fall at or below threshold
            db.get(`SELECT quantity FROM products WHERE id = ?`, [req.params.id], (err2, prod) => {
                if (err2 || !prod) return res.status(500).json({ error: 'Product not found.' });
                db.get(`SELECT value FROM settings WHERE key = 'lowStockThreshold'`, [], (err3, thRow) => {
                    const threshold = thRow ? parseInt(thRow.value, 10) : 8;
                    const resultingQty = prod.quantity + delta; // delta is negative
                    if (resultingQty <= threshold) {
                        return res.status(409).json({
                            error: 'LOW_STOCK_PROTECTION',
                            message: `Low Stock Protection is active. Cannot reduce stock of this item to ${resultingQty} — the minimum safe quantity is ${threshold + 1} units.`,
                            threshold,
                            currentQty: prod.quantity,
                            resultingQty
                        });
                    }
                    executeQuantityUpdate();
                });
            });
        });
    } else {
        executeQuantityUpdate();
    }

    function executeQuantityUpdate() {
        let sql, params;
        if (user) {
            sql = `UPDATE products SET quantity = quantity + ?, user = ? WHERE id = ?`;
            params = [delta, user, req.params.id];
        } else {
            sql = `UPDATE products SET quantity = quantity + ? WHERE id = ?`;
            params = [delta, req.params.id];
        }
        db.run(sql, params, function (err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true });
        });
    }
});

app.delete('/api/inventory/:id', (req, res) => {
    db.run(`DELETE FROM products WHERE id = ?`, [req.params.id], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Product deleted' });
    });
});

// =============================================
//  TRANSACTIONS API
// =============================================
app.get('/api/transactions', (req, res) => {
    db.all("SELECT * FROM transactions", [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/transactions', (req, res) => {
    const { id, product, category, type, quantity, unit, date, time, user } = req.body;

    const errors = [];
    const idErr = validateString(id, 'ID');
    const productErr = validateString(product, 'Product');
    const catErr = validateString(category, 'Category');
    const qtyErr = validateInt(quantity, 'Quantity', 1);
    const unitErr = validateString(unit, 'Unit');
    const dateErr = validateString(date, 'Date');
    const timeErr = validateString(time, 'Time');
    const userErr = validateString(user, 'User');
    if (idErr) errors.push(idErr);
    if (productErr) errors.push(productErr);
    if (catErr) errors.push(catErr);
    if (!['Stock In', 'Stock Out'].includes(type)) errors.push('Type must be "Stock In" or "Stock Out".');
    if (qtyErr) errors.push(qtyErr);
    if (unitErr) errors.push(unitErr);
    if (dateErr) errors.push(dateErr);
    if (timeErr) errors.push(timeErr);
    if (userErr) errors.push(userErr);
    if (errors.length > 0) return validationError(res, errors);

    const sql = `INSERT INTO transactions (id, product, category, type, quantity, unit, date, time, user) VALUES (?,?,?,?,?,?,?,?,?)`;
    db.run(sql, [id, product, category, type, parseInt(quantity, 10), unit, date, time, user], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, id });
    });
});

// NOTE: Specific routes must be defined BEFORE parameterized routes to avoid mis-matching.
// e.g. DELETE /api/transactions/type/Stock In must NOT match /:id with id='type'
app.delete('/api/transactions', (req, res) => {
    db.run(`DELETE FROM transactions`, [], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, message: 'All transactions cleared' });
    });
});

app.delete('/api/transactions/type/:type', (req, res) => {
    if (!['Stock In', 'Stock Out'].includes(req.params.type)) {
        return validationError(res, ['Type must be "Stock In" or "Stock Out".']);
    }
    db.run(`DELETE FROM transactions WHERE type = ?`, [req.params.type], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, message: `${req.params.type} transactions cleared` });
    });
});

app.delete('/api/transactions/:id', (req, res) => {
    db.run(`DELETE FROM transactions WHERE id = ?`, [req.params.id], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Transaction deleted' });
    });
});

// =============================================
//  EXPORT LOGS API
// =============================================
app.post('/api/export-logs', (req, res) => {
    const { user, type, date, time } = req.body;

    const errors = [];
    if (validateString(user, 'User')) errors.push(validateString(user, 'User'));
    if (validateString(type, 'Export Type')) errors.push(validateString(type, 'Export Type'));
    if (validateString(date, 'Date')) errors.push(validateString(date, 'Date'));
    if (validateString(time, 'Time')) errors.push(validateString(time, 'Time'));
    if (errors.length > 0) return validationError(res, errors);

    const sql = `INSERT INTO export_logs (user, type, date, time) VALUES (?,?,?,?)`;
    db.run(sql, [user, type, date, time], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, id: this.lastID });
    });
});

app.get('/api/export-logs', (req, res) => {
    db.all("SELECT * FROM export_logs ORDER BY id DESC LIMIT 20", [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.delete('/api/export-logs', (req, res) => {
    db.run(`DELETE FROM export_logs`, [], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, message: 'Export logs cleared' });
    });
});

// =============================================
//  SETTINGS API (Admin)
// =============================================
app.get('/api/settings', (req, res) => {
    db.all(`SELECT key, value FROM settings`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        // Return as a flat key-value object for easy client-side consumption
        const result = {};
        rows.forEach(r => result[r.key] = r.value);
        res.json(result);
    });
});

app.post('/api/settings', (req, res) => {
    const { key, value } = req.body;
    const keyErr = validateString(key, 'Key');
    if (keyErr) return validationError(res, [keyErr]);
    if (value === null || value === undefined) return validationError(res, ['Value is required.']);

    // Whitelist allowed setting keys to prevent arbitrary writes
    const ALLOWED_KEYS = ['lowStockProtectionEnabled', 'lowStockThreshold'];
    if (!ALLOWED_KEYS.includes(key)) {
        return res.status(400).json({ error: `Unknown setting key: ${key}` });
    }

    db.run(`INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
        [key, String(value)], function (err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, key, value });
        });
});

// =============================================
//  SYSTEM TOOLS
// =============================================
app.post('/api/system/restore', (req, res) => {
    const { users, products, transactions } = req.body;
    if (!users || !products || !transactions) {
        return validationError(res, ['Backup must contain users, products, and transactions arrays.']);
    }

    // Use db.serialize() with synchronous sqlite3 statement methods only.
    // db.serialize(async () => {}) does NOT work — sqlite3 cannot track async callbacks,
    // so the response would fire before all inserts complete (race condition).
    db.serialize(() => {
        db.run("DELETE FROM users");
        db.run("DELETE FROM products");
        db.run("DELETE FROM transactions");

        if (users && users.length) {
            const uStmt = db.prepare(`INSERT OR REPLACE INTO users VALUES (?,?,?,?,?,?)`);
            for (const u of users) {
                uStmt.run(u.id, u.name, u.username, u.password, u.role, u.status);
            }
            uStmt.finalize();
        }
        if (products && products.length) {
            const pStmt = db.prepare(`INSERT OR REPLACE INTO products VALUES (?,?,?,?,?,?,?)`);
            products.forEach(p => pStmt.run(p.id, p.name, p.category, p.unit, p.quantity, p.dateAdded, p.user));
            pStmt.finalize();
        }
        if (transactions && transactions.length) {
            const tStmt = db.prepare(`INSERT OR REPLACE INTO transactions VALUES (?,?,?,?,?,?,?,?,?)`);
            transactions.forEach(t => tStmt.run(t.id, t.product, t.category, t.type, t.quantity, t.unit, t.date, t.time, t.user));
            // Use finalize with a callback to only send the response AFTER all inserts complete
            tStmt.finalize((err) => {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ success: true, message: 'Restore completed' });
            });
        } else {
            // No transactions in backup — still need to respond after other ops are queued
            db.run('SELECT 1', () => {
                res.json({ success: true, message: 'Restore completed' });
            });
        }
    });
});

app.listen(PORT, () => {
    console.log(`Backend server running on http://localhost:${PORT}`);
});
