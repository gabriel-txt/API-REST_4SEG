const fs = require('fs');
const path = require('path');

const logFilePath = path.resolve(__dirname, '../logs.txt');

const logAction = (action, details) => {
    const timestamp = new Date().toISOString();
    const logMessage = `[${timestamp}] ${action}: ${JSON.stringify(details)}\n`;

    fs.appendFile(logFilePath, logMessage, (err) => {
        if (err) {
            console.error('Erro ao escrever no arquivo de log:', err.message);
        }
    });
};

module.exports = { logAction };