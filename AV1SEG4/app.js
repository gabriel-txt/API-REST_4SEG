require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const { check } = require('express-validator');
const db = require('./db/database');

const indexRouter = require('./rotas/index');
const authRouter = require('./rotas/auth');
const PORT = process.env.PORT || 8080;
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

app.use('/', indexRouter);
app.use('/auth', authRouter);

app.listen(PORT, function () {
	console.log(`Server running in: ${PORT}`);
})
