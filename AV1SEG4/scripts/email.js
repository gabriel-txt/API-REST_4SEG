const { createTransport } = require('nodemailer');
require('dotenv').config();

// Verificar se as variáveis do .env foram carregadas corretamente
console.log('EMAIL_HOST:', process.env.EMAIL_HOST);
console.log('EMAIL_USER:', process.env.EMAIL_USER);

const transporter = createTransport({
    host: process.env.EMAIL_HOST || 'smtp.gmail.com',
    port: 587, // Porta para STARTTLS (use 465 para SSL)
    secure: false, // false para 587, true para 465
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD,
    },
    tls: {
        rejectUnauthorized: false,
    },
});

const createPasswordResetUrl = (id, token) =>
    `${process.env.CLIENT_URI}/reset-password/${id}/${token}`;

const passwordResetTemplate = (user, url) => {
    const { email } = user;
    return {
        from: `Mail - <${process.env.EMAIL_USER}>`,
        to: email,
        subject: `Reset Password`,
        html: `
    <h2>Password Reset Link</h2>
    <p>Reset your password by clicking on the link below:</p>
    <a href=${url}><button>Reset Password</button></a>
    <br />
    <br />
    <small><a style="color: #38A169" href=${url}>${url}</a></small>
    <br />
    <small>The link will expire in 15 mins!</small>
    <small>If you haven't requested password reset, please ignore!</small>
    <br /><br />
    <p>Thanks,</p>
    <p>Authentication API</p>`,
    };
};

const passwordResetConfirmationTemplate = (user) => {
    const { email } = user;
    return {
        from: `Mail - <${process.env.EMAIL_USER}>`,
        to: email,
        subject: `Password Reset Successful`,
        html: `
    <h2>Password Reset Successful</h2>
    <p>You've successfully updated your password for your account <${email}>. </p>
    <small>If you did not change your password, reset it from your account.</small>
    <br /><br />
    <p>Thanks,</p>
    <p>Authentication API</p>`,
    };
};

const captchaTemplate = (user, captcha) => {
    const { email } = user;
    return {
        from: `Mail - <${process.env.EMAIL_USER}>`,
        to: email,
        subject: `Login CAPTCHA Verification`,
        html: `
    <h2>Login CAPTCHA Code</h2>
    <p>You entered an incorrect password. To continue, please use the following CAPTCHA code:</p>
    <p><strong>${captcha}</strong></p>
    <small>This code will be required for your next login attempt.</small>
    <br /><br />
    <p>Thanks,</p>
    <p>Authentication API</p>`,
    };
};

const twoFactorTemplate = (user, code) => {
    const { email } = user;
    return {
        from: `Mail - <${process.env.EMAIL_USER}>`,
        to: email,
        subject: `Two-Factor Authentication Code`,
        html: `
    <h2>Two-Factor Authentication Code</h2>
    <p>Please use the following code to complete your login:</p>
    <p><strong>${code}</strong></p>
    <small>This code will expire in 15 minutes.</small>
    <br /><br />
    <p>Thanks,</p>
    <p>Authentication API</p>`,
    };
};

module.exports = {
    transporter,
    createPasswordResetUrl,
    passwordResetTemplate,
    passwordResetConfirmationTemplate,
    captchaTemplate,
    twoFactorTemplate,
};