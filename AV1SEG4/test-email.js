const nodemailer = require('nodemailer');
require('dotenv').config(); // Carrega o .env

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});

const mailOptions = {
  from: process.env.EMAIL_USER,
  to: 'gabriel.p.r.gabriel@gmail.com',
  subject: 'Teste de Email',
  text: 'Este é um email de teste!',
};

transporter.sendMail(mailOptions, (err, info) => {
  if (err) {
    console.error('Erro ao enviar email:', err);
  } else {
    console.log('Email enviado:', info);
  }
});