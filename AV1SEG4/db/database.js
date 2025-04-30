const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const crypto = require('crypto');

// Conectar ao banco SQLite
const dbPath = path.resolve(__dirname, '../../database.sqlite');
const db = new sqlite3.Database(dbPath, (err) => {
if (err) {
    console.error('Erro ao conectar ao SQLite:', err.message);
} else {
    console.log('Conectado ao banco SQLite');
}
});

// Criar tabela de usuários, se não existir
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        salt TEXT NOT NULL,
        verified BOOLEAN DEFAULT FALSE,
        refreshtoken TEXT
        )
    `, (err) => {
    if (err) {
        console.error('Erro ao criar tabela users:', err.message);
    }
    });
});

// Funções de acesso ao banco
const dbOperations = {
    // Encontrar usuário por email
    findUserByEmail: (email, callback) => {
    db.get('SELECT * FROM users WHERE email = ?', [email], callback);
    },

    // Encontrar usuário por ID
    findUserById: (id, callback) => {
    db.get('SELECT * FROM users WHERE id = ?', [id], callback);
    },

    // Criar novo usuário
    createUser: (email, password, salt, callback) => {
    db.run('INSERT INTO users (email, password, salt) VALUES (?, ?, ?)', [email, password, salt], function(err) {
        if (err) return callback(err);
        callback(null, { id: this.lastID, email, password, salt});
    });
    },

    // Atualizar refresh token
    updateRefreshToken: (id, refreshToken, callback) => {
    db.run('UPDATE users SET refreshtoken = ? WHERE id = ?', [refreshToken, id], callback);
    },
    // Atualizar senha e salt
    updatePassword: (id, password, salt, callback) => {
        db.run('UPDATE users SET password = ?, salt = ? WHERE id = ?', [password, salt, id], callback);
    }
};

// Função para gerar salt e hash SHA256
const generateHash = (password) => {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.createHash('sha256').update(password + salt).digest('hex');
    return { salt, hash };
};

// Função para verificar senha
const verifyPassword = (password, salt, storedHash) => {
    const hash = crypto.createHash('sha256').update(password + salt).digest('hex');
    return hash === storedHash;
};

module.exports = { dbOperations, generateHash, verifyPassword };