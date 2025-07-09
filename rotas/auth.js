const express = require('express');
const router = express.Router();
const { check, validationResult } = require('express-validator');
const { verify } = require('jsonwebtoken');
const { dbOperations, generateHash, verifyPassword } = require('../db/database');
const { logAction } = require('../scripts/logger');

const {
    createAccessToken,
    createRefreshToken,
    sendAccessToken,
    sendRefreshToken,
    createPasswordResetToken,
} = require('../scripts/tokens');
const {
    transporter,
    createPasswordResetUrl,
    passwordResetTemplate,
    passwordResetConfirmationTemplate,
    captchaTemplate,
    twoFactorTemplate,
} = require('../scripts/email');
const { protected } = require('../scripts/protected');

router.get('/', async (req, res) => {
    res.send('Hello Express!! 👋, this is Auth end point');
});

// Validação e sanitização para signup
const signupValidation = [
    check('username')
        .trim()
        .escape()
        .notEmpty().withMessage('Username is required')
        .isAlphanumeric().withMessage('Username must be alphanumeric'),
    check('password')
        .trim()
        .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/).withMessage('Password must contain at least one lowercase letter, one uppercase letter, and one number')
        .trim().escape(),
    check('nome')
        .trim().escape()
        .notEmpty().withMessage('Name is required')
        .matches(/^[A-Za-zÀ-ÖØ-öø-ÿ\s']+$/).withMessage('Name must contain only letters'),
    check('email')
        .normalizeEmail()
        .trim()
        .isEmail().withMessage('Invalid email'),
    check('perfil').trim().escape().optional().isIn(['admin', 'user']).withMessage('Invalid profile value'),
];

// Rota de Registro de usuário
router.post('/signup', signupValidation, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            logAction('Signup Failed - Invalid Input', { errors: errors.array() });
            return res.status(400).json({
                message: 'Valor inválido',
                type: 'error',
                errors: errors.array(),
            });
        }

        const { username, password, nome, email } = req.body;
        const perfil = req.body.perfil || "admin";

        // Verifica se o usuário já existe no db
        dbOperations.findUserByUsername(username, async (err, user) => {
            if (err) {
                logAction('Signup Failed - Database Error', { error: err.message });
                return res.status(500).json({
                    message: 'Erro checando usuário!',
                    type: 'error',
                    error: err,
                });
            }
            if (user) {
                logAction('Signup Failed - User Exists', { username });
                return res.status(400).json({
                    message: 'Usuário já existe! Tente se logar. 😄',
                    type: 'warning',
                });
            }

            const { salt, hash } = generateHash(password);

            // Cria o usuário
            dbOperations.createUser(username, hash, salt, nome, email, perfil, (err, newUser) => {
                if (err) {
                    logAction('Signup Failed - Creation Error', { error: err.message });
                    return res.status(500).json({
                        message: 'Erro na criação de usuário!',
                        type: 'error',
                        error: err,
                    });
                }

                logAction('Signup Successful', { username, email, perfil });
                res.status(200).json({
                    message: 'Usuário criado com sucesso! 🥳',
                    type: 'success',
                });
            });
        });
    } catch (error) {
        logAction('Signup Failed - Unexpected Error', { error: error.message });
        console.log('Error: ', error);
        res.status(500).json({
            type: 'error',
            message: 'Erro na criação de usuário!',
            error,
        });
    }
});

// Validação e sanitização para signin
const signinValidation = [
    check('username')
        .trim().escape()
        .notEmpty().withMessage('Username is required')
        .isAlphanumeric().withMessage('Username must contain only letters and numbers'),
    check('password')
        .trim().escape()
        .notEmpty().withMessage('Password is required')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/).withMessage('Password must contain only lowercase, uppercase letters, and numbers'),
    check('captcha')
        .trim().escape().optional()
        .isNumeric().withMessage('CAPTCHA must be numeric')
];

// Rota de login de usuário
router.post('/signin', signinValidation, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            logAction('Signin Failed - Invalid Input', { errors: errors.array() });
            return res.status(400).json({
                message: 'Valor inválido',
                type: 'error',
                errors: errors.array(),
            });
        }

        const { username, password, captcha } = req.body;

        // Verifica se o usuário existe
        dbOperations.findUserByUsername(username, async (err, user) => {
            if (err || !user) {
                logAction('Signin Failed - User Not Found', { username });
                return res.status(400).json({
                    message: "Usuário não existe! 😢",
                    type: 'error',
                });
            }

            // Verifica se há um CAPTCHA pendente
            if (user.captcha) {
                if (!captcha) {
                    logAction('Signin Failed - CAPTCHA Required', { username, userEmail: user.email });
                    return res.status(400).json({
                        message: 'CAPTCHA requerido! Por favor, digite o código enviado por email. 🔐',
                        type: 'error',
                        requiresCaptcha: true,
                    });
                }

                // Se o CAPTCHA existe verifica se ele está correto
                if (captcha !== user.captcha) {
                    logAction('Signin Failed - Invalid CAPTCHA', { username, userEmail: user.email, captcha });
                    return res.status(400).json({
                        message: 'CAPTCHA inválido! Por favor, tente novamente. 🔐',
                        type: 'error',
                        requiresCaptcha: true,
                    });
                }

                // CAPTCHA válido, limpar do banco
                dbOperations.clearCaptcha(user.id, (err) => {
                    if (err) {
                        logAction('Signin Failed - Error Clearing CAPTCHA', { username, userEmail: user.email, error: err.message });
                    }
                });
            }

            // Se a senha estiver errada, gera o CAPTCHA
            const isMatch = verifyPassword(password, user.salt, user.password);
            if (!isMatch) {
                // Gerar CAPTCHA de 6 dígitos
                const captchaCode = Math.floor(100000 + Math.random() * 900000).toString();
                dbOperations.saveCaptcha(user.id, captchaCode, (err) => {
                    if (err) {
                        logAction('Signin Failed - Error Saving CAPTCHA', { username, userEmail: user.email, error: err.message });
                        return res.status(500).json({
                            message: 'Erro ao gerar o CAPTCHA!',
                            type: 'error',
                            error: err.message,
                        });
                    }

                    // Enviar CAPTCHA por email usando user.email
                    const mailOptions = captchaTemplate(user, captchaCode);
                    console.log('Enviando CAPTCHA para:', user.email); // Log para depuração
                    transporter.sendMail(mailOptions, (err, info) => {
                        if (err) {
                            logAction('Signin Failed - Error Sending CAPTCHA Email', { username, userEmail: user.email, error: err.message });
                            return res.status(500).json({
                                message: 'Erro ao enviar CAPTCHA por email! 😢',
                                type: 'error',
                                error: err.message,
                            });
                        }

                        logAction('Signin Failed - CAPTCHA Sent', { username, userEmail: user.email, captchaCode });
                        return res.status(401).json({ // Não informar senha inválida
                            message: 'Senha incorreta! O CAPTCHA foi enviado ao seu email. 🔐',
                            type: 'error',
                            requiresCaptcha: true,
                        });
                    });
                });
                return;
            }

            // Gerar código de segundo fator de autenticação
            const twoFactorCode = Math.floor(100000 + Math.random() * 900000).toString();
            dbOperations.saveTwoFactorCode(user.id, twoFactorCode, (err) => {
                if (err) {
                    logAction('Signin Failed - Error Saving 2FA Code', { username, userEmail: user.email, error: err.message });
                    return res.status(500).json({
                        message: 'Erro gerando código de segundo fator!',
                        type: 'error',
                        error: err.message,
                    });
                }

                // Enviar código de 2FA por email usando user.email
                const mailOptions = twoFactorTemplate(user, twoFactorCode);
                console.log('Enviando 2FA para:', user.email); // Log para depuração
                transporter.sendMail(mailOptions, (err, info) => {
                    if (err) {
                        logAction('Signin Failed - Error Sending 2FA Email', { username, userEmail: user.email, error: err.message });
                        return res.status(500).json({
                            message: 'Erro enviando código de segundo fator ao email! 😢',
                            type: 'error',
                            error: err.message,
                        });
                    }

                    logAction('Signin - 2FA Code Sent', { username, userEmail: user.email, twoFactorCode });
                    return res.status(200).json({
                        message: 'Código de segundo fator de autentificação enviado por email! 📧',
                        type: 'success',
                        requires2FA: true,
                        userId: user.id,
                    });
                });
            });
        });
    } catch (error) {
        logAction('Signin Failed - Unexpected Error', { error: error.message });
        console.log('Error: ', error);
        res.status(500).json({
            type: 'error',
            message: 'Erro no login!',
            error,
        });
    }
});

// Validação e sanitização para verificação de 2FA
const twoFactorValidation = [
    check('userId')
        .isInt().withMessage('User ID must be an integer'),
    check('code')
        .trim().escape()
        .notEmpty().withMessage('Two-factor code is required')
        .isLength({ min: 6, max: 6 }).withMessage('Code must be 6 digits')
        .isNumeric().withMessage('Code must be numeric')
];

// Rota de verificação de 2FA
router.post('/verify-2fa', twoFactorValidation, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            logAction('2FA Verification Failed - Invalid Input', { errors: errors.array() });
            return res.status(400).json({
                message: 'Valor inválido',
                type: 'error',
                errors: errors.array(),
            });
        }

        
        const { userId, code } = req.body;

        dbOperations.findUserById(userId, (err, user) => {
            if (err || !user) {
                logAction('2FA Verification Failed - User Not Found', { userId });
                return res.status(400).json({
                    message: "Usuário não existe! 😢",
                    type: 'error',
                });
            }

            if (!user.twoFactorCode) {
                logAction('2FA Verification Failed - No Code Pending', { userId });
                return res.status(400).json({
                    message: 'Sem código de segundo fator pendente! Por favor, se logue novamente. 🔐',
                    type: 'error',
                });
            }

            if (user.twoFactorCode !== code) {
                logAction('2FA Verification Failed - Invalid Code', { userId, code });
                return res.status(400).json({
                    message: 'Código de segundo fator inválido! Por favor, tente novamente. 🔐',
                    type: 'error',
                });
            }

            // Código 2FA válido, limpar do banco
            dbOperations.clearTwoFactorCode(user.id, (err) => {
                if (err) {
                    logAction('2FA Verification Failed - Error Clearing Code', { userId, error: err.message });
                }
            });

            const accessToken = createAccessToken(user.id);
            const refreshToken = createRefreshToken(user.id);

            dbOperations.updateRefreshToken(user.id, refreshToken, (err) => {
                if (err) {
                    logAction('2FA Verification Failed - Error Saving Refresh Token', { userId, error: err.message });
                    return res.status(500).json({
                        message: 'Erro ao salvar o token de atualização!',
                        type: 'error',
                        error: err,
                    });
                }

                sendRefreshToken(res, refreshToken);
                sendAccessToken(req, res, accessToken);
                logAction('2FA Verification Successful', { userId });
            });
        });
    } catch (error) {
        logAction('2FA Verification Failed - Unexpected Error', { error: error.message });
        console.log('Error: ', error);
        res.status(500).json({
            type: 'error',
            message: 'Erro verificando código de segundo fator!',
            error,
        });
    }
});

// Rota de Saída do usuário
router.post('/logout', (_req, res) => {
    res.clearCookie('refreshtoken');
    logAction('Logout Successful', {});
    return res.json({
        message: 'Deslogado com sucesso! 🤗',
        type: 'success',
    });
});

// Rota de token de atualização
router.post('/refresh_token', async (req, res) => {
    try {
        const { refreshtoken } = req.cookies;
        if (!refreshtoken) {
            logAction('Refresh Token Failed - No Token', {});
            return res.status(500).json({
                message: 'Sem token de atualização! 🤔',
                type: 'error',
            });
        }

        let id;
        try {
            id = verify(refreshtoken, process.env.REFRESH_TOKEN_SECRET).id;
        } catch (error) {
            logAction('Refresh Token Failed - Invalid Token', { error: error.message });
            return res.status(500).json({
                message: 'Token de atualização inválido! 🤔',
                type: 'error',
            });
        }

        if (!id) {
            logAction('Refresh Token Failed - Invalid Token', {});
            return res.status(500).json({
                message: 'Token de atualização inválido! 🤔',
                type: 'error',
            });
        }

        dbOperations.findUserById(id, (err, user) => {
            if (err || !user) {
                logAction('Refresh Token Failed - User Not Found', { id });
                return res.status(500).json({
                    message: "Usuário não existe! 😢",
                    type: 'error',
                });
            }

            if (user.refreshtoken !== refreshtoken) {
                logAction('Refresh Token Failed - Token Mismatch', { id });
                return res.status(500).json({
                    message: 'Token de atualização inválido! 🤔',
                    type: 'error',
                });
            }

            const accessToken = createAccessToken(user.id);
            const refreshToken = createRefreshToken(user.id);

            dbOperations.updateRefreshToken(user.id, refreshToken, (err) => {
                if (err) {
                    logAction('Refresh Token Failed - Error Saving Token', { id, error: err.message });
                    return res.status(500).json({
                        message: 'Erro ao salvar o token de atualização!',
                        type: 'error',
                        error: err,
                    });
                }

                sendRefreshToken(res, refreshToken);
                logAction('Refresh Token Successful', { id });
                return res.json({
                    message: 'Token atualizado com sucesso! 🤗',
                    type: 'success',
                    accessToken,
                });
            });
        });
    } catch (error) {
        logAction('Refresh Token Failed - Unexpected Error', { error: error.message });
        console.log('Error: ', error);
        res.status(500).json({
            type: 'error',
            message: 'Erro ao atualizar token!',
            error,
        });
    }
});

router.get('/protected', protected, async (req, res) => {
    try {
        if (req.user) {
            logAction('Access Protected Route', { userId: req.user.id });
            return res.json({
                message: 'Você está logado! 🤗',
                type: 'success',
                user: req.user,
            });
        }

        logAction('Access Protected Route Failed - Not Logged In');
        return res.status(500).json({
            message: 'Você não está logado! 😢',
            type: 'error',
        });
    } catch (error) {
        logAction('Access Protected Route Failed - Unexpected Error', { error: error.message });
        res.status(500).json({
            type: 'error',
            message: 'Erro ao obter rota protegida!',
            error,
        });
    }
});

// Validação e sanitização para send-password-reset-email
const passwordResetValidation = [
    check('email')
        .normalizeEmail()
        .isEmail().withMessage('Invalid email')
];

// Rota de reset de senha por email
router.post('/send-password-reset-email', passwordResetValidation, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            logAction('Send Password Reset Email Failed - Invalid Input', { errors: errors.array() });
            return res.status(400).json({
                message: 'Email inválido',
                type: 'error',
                errors: errors.array(),
            });
        }

        const { email } = req.body;

        dbOperations.findUserByEmail(email, async (err, user) => {
            if (err || !user) {
                logAction('Send Password Reset Email Failed - User Not Found', { email });
                return res.status(500).json({
                    message: "Usuário não existe! 😢",
                    type: 'error',
                });
            }

            const token = createPasswordResetToken(user);
            const url = createPasswordResetUrl(user.id, token);
            console.log('ID do usuário:', user.id, 'Token gerado:', token, 'URL:', url);

            const mailOptions = passwordResetTemplate(user, url);
            transporter.sendMail(mailOptions, (err, info) => {
                console.log('Erro de envio de email:', err, 'Info:', info);
                if (err) {
                    logAction('Send Password Reset Email Failed - Email Error', { email, error: err.message });
                    return res.status(500).json({
                        message: 'Erro ao enviar email! 😢',
                        type: 'error',
                        error: err.message,
                    });
                }

                logAction('Send Password Reset Email Successful', { email });
                return res.json({
                    message: 'Link para resetar senha foi enviado por email! 📧',
                    type: 'success',
                });
            });
        });
    } catch (error) {
        logAction('Send Password Reset Email Failed - Unexpected Error', { error: error.message });
        console.log('Error: ', error);
        res.status(500).json({
            type: 'error',
            message: 'Erro ao enviar email!',
            error,
        });
    }
});

// Validação e sanitização para reset-password
const resetPasswordValidation = [
    check('newPassword')
        .trim()
        .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/).withMessage('Password must contain at least one lowercase letter, one uppercase letter, and one number')
];

// Rota de reset de senha
router.post('/reset-password/:id/:token', resetPasswordValidation, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            logAction('Reset Password Failed - Invalid Input', { errors: errors.array() });
            return res.status(400).json({
                message: 'Valor inválido',
                type: 'error',
                errors: errors.array(),
            });
        }

        const { id, token } = req.params;
        const { newPassword } = req.body;

        dbOperations.findUserById(id, async (err, user) => {
            if (err || !user) {
                logAction('Reset Password Failed - User Not Found', { id });
                return res.status(500).json({
                    message: "Usuário não existe! 😢",
                    type: 'error',
                });
            }

            let isValid;
            try {
                isValid = verify(token, process.env.VERIFY_EMAIL_TOKEN_SECRET);
            } catch (error) {
                logAction('Reset Password Failed - Invalid Token', { id, error: error.message });
                return res.status(500).json({
                    message: 'Token inválido! 😢',
                    type: 'error',
                });
            }

            if (!isValid) {
                logAction('Reset Password Failed - Invalid Token', { id });
                return res.status(500).json({
                    message: 'Token inválido! 😢',
                    type: 'error',
                });
            }

            const { salt, hash } = generateHash(newPassword);

            dbOperations.updatePassword(user.id, hash, salt, async (err) => {
                if (err) {
                    logAction('Reset Password Failed - Error Updating Password', { id, error: err.message });
                    return res.status(500).json({
                        message: 'Erro na troca de senha!',
                        type: 'error',
                        error: err,
                    });
                }

                const mailOptions = passwordResetConfirmationTemplate(user);
                transporter.sendMail(mailOptions, (err) => {
                    if (err) {
                        logAction('Reset Password Failed - Error Sending Confirmation Email', { id, error: err.message });
                        return res.status(500).json({
                            message: 'Erro ao enviar email! 😢',
                            type: 'error',
                        });
                    }

                    logAction('Reset Password Successful', { id });
                    return res.json({
                        message: 'Email enviado! 📧',
                        type: 'success',
                    });
                });
            });
        });
    } catch (error) {
        logAction('Reset Password Failed - Unexpected Error', { error: error.message });
        res.status(500).json({
            type: 'error',
            message: 'Erro ao enviar email!',
            error,
        });
    }
});

module.exports = router;