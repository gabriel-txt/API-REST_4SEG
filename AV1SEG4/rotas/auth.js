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
    check('username').trim().escape().notEmpty().withMessage('Username is required'),
    check('password')
        .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/).withMessage('Password must contain at least one lowercase letter, one uppercase letter, and one number')
        .trim().escape(),
    check('nome').trim().escape().notEmpty().withMessage('Name is required'),
    check('email').isEmail().withMessage('Invalid email'),
    check('perfil').trim().escape().optional(),
];

router.post('/signup', signupValidation, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            logAction('Signup Failed - Invalid Input', { errors: errors.array() });
            return res.status(400).json({
                message: 'Invalid input',
                type: 'error',
                errors: errors.array(),
            });
        }

        const { username, password, nome, email } = req.body;
        const perfil = req.body.perfil || "admin";

        dbOperations.findUserByUsername(username, async (err, user) => {
            if (err) {
                logAction('Signup Failed - Database Error', { error: err.message });
                return res.status(500).json({
                    message: 'Error checking user!',
                    type: 'error',
                    error: err,
                });
            }
            if (user) {
                logAction('Signup Failed - User Exists', { username });
                return res.status(400).json({
                    message: 'User already exists! Try logging in. 😄',
                    type: 'warning',
                });
            }

            const { salt, hash } = generateHash(password);

            dbOperations.createUser(username, hash, salt, nome, email, perfil, (err, newUser) => {
                if (err) {
                    logAction('Signup Failed - Creation Error', { error: err.message });
                    return res.status(500).json({
                        message: 'Error creating user!',
                        type: 'error',
                        error: err,
                    });
                }

                logAction('Signup Successful', { username, email, perfil });
                res.status(200).json({
                    message: 'User created successfully! 🥳',
                    type: 'success',
                });
            });
        });
    } catch (error) {
        logAction('Signup Failed - Unexpected Error', { error: error.message });
        console.log('Error: ', error);
        res.status(500).json({
            type: 'error',
            message: 'Error creating user!',
            error,
        });
    }
});

// Validação e sanitização para signin
const signinValidation = [
    check('username').trim().escape().notEmpty().withMessage('Username is required'),
    check('password').trim().escape().notEmpty().withMessage('Password is required'),
    check('captcha').trim().escape().optional(),
];

router.post('/signin', signinValidation, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            logAction('Signin Failed - Invalid Input', { errors: errors.array() });
            return res.status(400).json({
                message: 'Invalid input',
                type: 'error',
                errors: errors.array(),
            });
        }

        const { username, password, captcha } = req.body;

        dbOperations.findUserByUsername(username, async (err, user) => {
            if (err || !user) {
                logAction('Signin Failed - User Not Found', { username });
                return res.status(400).json({
                    message: "User doesn't exist! 😢",
                    type: 'error',
                });
            }

            // Verificar se há um CAPTCHA pendente
            if (user.captcha) {
                if (!captcha) {
                    logAction('Signin Failed - CAPTCHA Required', { username, userEmail: user.email });
                    return res.status(400).json({
                        message: 'CAPTCHA required! Please provide the code sent to your email. 🔐',
                        type: 'error',
                        requiresCaptcha: true,
                    });
                }

                if (captcha !== user.captcha) {
                    logAction('Signin Failed - Invalid CAPTCHA', { username, userEmail: user.email, captcha });
                    return res.status(400).json({
                        message: 'Invalid CAPTCHA! Please try again. 🔐',
                        type: 'error',
                        requiresCaptcha: true,
                    });
                }

                // CAPTCHA válido, limpar do banco
                dbOperations.clearCaptcha(user.id, (err) => {
                    if (err) {
                        logAction('Signin Failed - Error Clearing CAPTCHA', { username, userEmail: user.email, error: err.message });
                        console.error('Error clearing CAPTCHA:', err);
                    }
                });
            }

            const isMatch = verifyPassword(password, user.salt, user.password);
            if (!isMatch) {
                // Gerar CAPTCHA de 6 dígitos
                const captchaCode = Math.floor(100000 + Math.random() * 900000).toString();
                dbOperations.saveCaptcha(user.id, captchaCode, (err) => {
                    if (err) {
                        logAction('Signin Failed - Error Saving CAPTCHA', { username, userEmail: user.email, error: err.message });
                        return res.status(500).json({
                            message: 'Error generating CAPTCHA!',
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
                                message: 'Error sending CAPTCHA email! 😢',
                                type: 'error',
                                error: err.message,
                            });
                        }

                        logAction('Signin Failed - CAPTCHA Sent', { username, userEmail: user.email, captchaCode });
                        return res.status(401).json({
                            message: 'Password is incorrect! A CAPTCHA has been sent to your email. 🔐',
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
                        message: 'Error generating two-factor code!',
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
                            message: 'Error sending two-factor email! 😢',
                            type: 'error',
                            error: err.message,
                        });
                    }

                    logAction('Signin - 2FA Code Sent', { username, userEmail: user.email, twoFactorCode });
                    return res.status(200).json({
                        message: 'Two-factor authentication code sent to your email! 📧',
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
            message: 'Error signing in!',
            error,
        });
    }
});

// Validação e sanitização para verificação de 2FA
const twoFactorValidation = [
    check('userId').isInt().withMessage('User ID must be an integer'),
    check('code').trim().escape().notEmpty().withMessage('Two-factor code is required'),
];

router.post('/verify-2fa', twoFactorValidation, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            logAction('2FA Verification Failed - Invalid Input', { errors: errors.array() });
            return res.status(400).json({
                message: 'Invalid input',
                type: 'error',
                errors: errors.array(),
            });
        }

        const { userId, code } = req.body;

        dbOperations.findUserById(userId, (err, user) => {
            if (err || !user) {
                logAction('2FA Verification Failed - User Not Found', { userId });
                return res.status(400).json({
                    message: "User doesn't exist! 😢",
                    type: 'error',
                });
            }

            if (!user.twoFactorCode) {
                logAction('2FA Verification Failed - No Code Pending', { userId });
                return res.status(400).json({
                    message: 'No two-factor code pending! Please sign in again. 🔐',
                    type: 'error',
                });
            }

            if (user.twoFactorCode !== code) {
                logAction('2FA Verification Failed - Invalid Code', { userId, code });
                return res.status(400).json({
                    message: 'Invalid two-factor code! Please try again. 🔐',
                    type: 'error',
                });
            }

            // Código 2FA válido, limpar do banco
            dbOperations.clearTwoFactorCode(user.id, (err) => {
                if (err) {
                    logAction('2FA Verification Failed - Error Clearing Code', { userId, error: err.message });
                    console.error('Error clearing 2FA code:', err);
                }
            });

            const accessToken = createAccessToken(user.id);
            const refreshToken = createRefreshToken(user.id);

            dbOperations.updateRefreshToken(user.id, refreshToken, (err) => {
                if (err) {
                    logAction('2FA Verification Failed - Error Saving Refresh Token', { userId, error: err.message });
                    return res.status(500).json({
                        message: 'Error saving refresh token!',
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
            message: 'Error verifying two-factor code!',
            error,
        });
    }
});

router.post('/logout', (_req, res) => {
    res.clearCookie('refreshtoken');
    logAction('Logout Successful', {});
    return res.json({
        message: 'Logged out successfully! 🤗',
        type: 'success',
    });
});

router.post('/refresh_token', async (req, res) => {
    try {
        const { refreshtoken } = req.cookies;
        if (!refreshtoken) {
            logAction('Refresh Token Failed - No Token', {});
            return res.status(500).json({
                message: 'No refresh token! 🤔',
                type: 'error',
            });
        }

        let id;
        try {
            id = verify(refreshtoken, process.env.REFRESH_TOKEN_SECRET).id;
        } catch (error) {
            logAction('Refresh Token Failed - Invalid Token', { error: error.message });
            return res.status(500).json({
                message: 'Invalid refresh token! 🤔',
                type: 'error',
            });
        }

        if (!id) {
            logAction('Refresh Token Failed - Invalid Token', {});
            return res.status(500).json({
                message: 'Invalid refresh token! 🤔',
                type: 'error',
            });
        }

        dbOperations.findUserById(id, (err, user) => {
            if (err || !user) {
                logAction('Refresh Token Failed - User Not Found', { id });
                return res.status(500).json({
                    message: "User doesn't exist! 😢",
                    type: 'error',
                });
            }

            if (user.refreshtoken !== refreshtoken) {
                logAction('Refresh Token Failed - Token Mismatch', { id });
                return res.status(500).json({
                    message: 'Invalid refresh token! 🤔',
                    type: 'error',
                });
            }

            const accessToken = createAccessToken(user.id);
            const refreshToken = createRefreshToken(user.id);

            dbOperations.updateRefreshToken(user.id, refreshToken, (err) => {
                if (err) {
                    logAction('Refresh Token Failed - Error Saving Token', { id, error: err.message });
                    return res.status(500).json({
                        message: 'Error saving refresh token!',
                        type: 'error',
                        error: err,
                    });
                }

                sendRefreshToken(res, refreshToken);
                logAction('Refresh Token Successful', { id });
                return res.json({
                    message: 'Refreshed successfully! 🤗',
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
            message: 'Error refreshing token!',
            error,
        });
    }
});

router.get('/protected', protected, async (req, res) => {
    try {
        if (req.user) {
            logAction('Access Protected Route', { userId: req.user.id });
            return res.json({
                message: 'You are logged in! 🤗',
                type: 'success',
                user: req.user,
            });
        }

        logAction('Access Protected Route Failed - Not Logged In', {});
        return res.status(500).json({
            message: 'You are not logged in! 😢',
            type: 'error',
        });
    } catch (error) {
        logAction('Access Protected Route Failed - Unexpected Error', { error: error.message });
        res.status(500).json({
            type: 'error',
            message: 'Error getting protected route!',
            error,
        });
    }
});

// Validação e sanitização para send-password-reset-email
const passwordResetValidation = [
    check('email').isEmail()
];

router.post('/send-password-reset-email', passwordResetValidation, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            logAction('Send Password Reset Email Failed - Invalid Input', { errors: errors.array() });
            return res.status(400).json({
                message: 'Invalid email',
                type: 'error',
                errors: errors.array(),
            });
        }

        const { email } = req.body;

        dbOperations.findUserByEmail(email, async (err, user) => {
            if (err || !user) {
                logAction('Send Password Reset Email Failed - User Not Found', { email });
                return res.status(500).json({
                    message: "User doesn't exist! 😢",
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
                        message: 'Error sending email! 😢',
                        type: 'error',
                        error: err.message,
                    });
                }

                logAction('Send Password Reset Email Successful', { email });
                return res.json({
                    message: 'Password reset link has been sent to your email! 📧',
                    type: 'success',
                });
            });
        });
    } catch (error) {
        logAction('Send Password Reset Email Failed - Unexpected Error', { error: error.message });
        console.log('Error: ', error);
        res.status(500).json({
            type: 'error',
            message: 'Error sending email!',
            error,
        });
    }
});

// Validação e sanitização para reset-password
const resetPasswordValidation = [
    check('newPassword')
        .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/).withMessage('Password must contain at least one lowercase letter, one uppercase letter, and one number')
        .trim().escape()
];

router.post('/reset-password/:id/:token', resetPasswordValidation, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            logAction('Reset Password Failed - Invalid Input', { errors: errors.array() });
            return res.status(400).json({
                message: 'Invalid input',
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
                    message: "User doesn't exist! 😢",
                    type: 'error',
                });
            }

            let isValid;
            try {
                isValid = verify(token, process.env.VERIFY_EMAIL_TOKEN_SECRET);
            } catch (error) {
                logAction('Reset Password Failed - Invalid Token', { id, error: error.message });
                return res.status(500).json({
                    message: 'Invalid token! 😢',
                    type: 'error',
                });
            }

            if (!isValid) {
                logAction('Reset Password Failed - Invalid Token', { id });
                return res.status(500).json({
                    message: 'Invalid token! 😢',
                    type: 'error',
                });
            }

            const { salt, hash } = generateHash(newPassword);

            dbOperations.updatePassword(user.id, hash, salt, async (err) => {
                if (err) {
                    logAction('Reset Password Failed - Error Updating Password', { id, error: err.message });
                    return res.status(500).json({
                        message: 'Error updating password!',
                        type: 'error',
                        error: err,
                    });
                }

                const mailOptions = passwordResetConfirmationTemplate(user);
                transporter.sendMail(mailOptions, (err) => {
                    if (err) {
                        logAction('Reset Password Failed - Error Sending Confirmation Email', { id, error: err.message });
                        return res.status(500).json({
                            message: 'Error sending email! 😢',
                            type: 'error',
                        });
                    }

                    logAction('Reset Password Successful', { id });
                    return res.json({
                        message: 'Email sent! 📧',
                        type: 'success',
                    });
                });
            });
        });
    } catch (error) {
        logAction('Reset Password Failed - Unexpected Error', { error: error.message });
        res.status(500).json({
            type: 'error',
            message: 'Error sending email!',
            error,
        });
    }
});

module.exports = router;