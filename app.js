require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const { check } = require('express-validator');
const db = require('./db/database');
const cors = require('cors');

const indexRouter = require('./rotas/index');
const authRouter = require('./rotas/auth');
const PORT = process.env.PORT || 8080;
const app = express();

// Configurar CORS para refletir a origem da requisição
app.use(cors({
    origin: function (origin, callback) {
        // Permitir requisições de qualquer origem, incluindo 'null'
        callback(null, true);
    },
    credentials: true // Permitir cookies/sessões
}));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

app.get('/auth/protected', (req, res) => {
    if (req.session && req.session.user) {
        res.json({
            message: 'Bem-vindo!',
            user: {
                name: req.session.user.nome || 'Usuário Anônimo',
                email: req.session.user.email || 'email@exemplo.com'
            }
        });
    } else {
        res.status(401).json({ message: 'Não autenticado' });
    }
});

app.use('/', indexRouter);
app.use('/auth', authRouter);

console.log('Chegou aqui');

app.listen(PORT, function () {
    console.log(`Server running in: ${PORT}`);
});