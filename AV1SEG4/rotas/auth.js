const express = require('express');
const router = express.Router();
const { check, validationResult } = require('express-validator');
const { verify } = require('jsonwebtoken');
const { dbOperations, generateHash, verifyPassword } = require('../db/database');

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
} = require('../scripts/email');
const { protected } = require('../scripts/protected');

/* GET main auth page. */
router.get('/', async (req, res) => {
	res.send('Hello Express!! 👋, this is Auth end point');
});

/* Validação e sanitização para signup */
const signupValidation = [
	check('email').isEmail().normalizeEmail(),
	check('password')
		.isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
		.matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/).withMessage('Password must contain at least one lowercase letter, one uppercase letter, and one number')
		.trim().escape()
];

router.post('/signup', signupValidation, async (req, res) => {
	try {
		const errors = validationResult(req);
		if (!errors.isEmpty()) {
			return res.status(400).json({
				message: 'Invalid input',
				type: 'error',
				errors: errors.array(),
			});
		}

		const { email, password } = req.body;

		dbOperations.findUserByEmail(email, async (err, user) => {
			if (err) {
				return res.status(500).json({
					message: 'Error checking user!',
					type: 'error',
					error: err,
				});
			}
			if (user) {
				return res.status(500).json({
					message: 'User already exists! Try logging in. 😄',
					type: 'warning',
				});
			}

			const { salt, hash } = generateHash(password);

			dbOperations.createUser(email, hash, salt, (err, newUser) => {
				if (err) {
					return res.status(500).json({
						message: 'Error creating user!',
						type: 'error',
						error: err,
					});
				}

				res.status(200).json({
					message: 'User created successfully! 🥳',
					type: 'success',
				});
			});
		});
	} catch (error) {
		console.log('Error: ', error);
		res.status(500).json({
			type: 'error',
			message: 'Error creating user!',
			error,
		});
	}
});

/* Validação e sanitização para signin */
const signinValidation = [
	check('email').isEmail().normalizeEmail(),
	check('password').trim().escape()
];

router.post('/signin', signinValidation, async (req, res) => {
	try {
		const errors = validationResult(req);
		if (!errors.isEmpty()) {
			return res.status(400).json({
				message: 'Invalid input',
				type: 'error',
				errors: errors.array(),
			});
		}

		const { email, password } = req.body;

		dbOperations.findUserByEmail(email, async (err, user) => {
			if (err || !user) {
				return res.status(500).json({
					message: "User doesn't exist! 😢",
					type: 'error',
				});
			}

			const isMatch = verifyPassword(password, user.salt, user.password);
			if (!isMatch) {
				return res.status(500).json({
					message: 'Password is incorrect! ⚠️',
					type: 'error',
				});
			}

			const accessToken = createAccessToken(user.id);
			const refreshToken = createRefreshToken(user.id);

			dbOperations.updateRefreshToken(user.id, refreshToken, (err) => {
				if (err) {
					return res.status(500).json({
						message: 'Error saving refresh token!',
						type: 'error',
						error: err,
					});
				}

				sendRefreshToken(res, refreshToken);
				sendAccessToken(req, res, accessToken);
			});
		});
	} catch (error) {
		console.log('Error: ', error);
		res.status(500).json({
			type: 'error',
			message: 'Error signing in!',
			error,
		});
	}
});

router.post('/logout', (_req, res) => {
	res.clearCookie('refreshtoken');
	return res.json({
		message: 'Logged out successfully! 🤗',
		type: 'success',
	});
});

router.post('/refresh_token', async (req, res) => {
	try {
		const { refreshtoken } = req.cookies;
		if (!refreshtoken) {
			return res.status(500).json({
				message: 'No refresh token! 🤔',
				type: 'error',
			});
		}

		let id;
		try {
			id = verify(refreshtoken, process.env.REFRESH_TOKEN_SECRET).id;
		} catch (error) {
			return res.status(500).json({
				message: 'Invalid refresh token! 🤔',
				type: 'error',
			});
		}

		if (!id) {
			return res.status(500).json({
				message: 'Invalid refresh token! 🤔',
				type: 'error',
			});
		}

		dbOperations.findUserById(id, (err, user) => {
			if (err || !user) {
				return res.status(500).json({
					message: "User doesn't exist! 😢",
					type: 'error',
				});
			}

			if (user.refreshtoken !== refreshtoken) {
				return res.status(500).json({
					message: 'Invalid refresh token! 🤔',
					type: 'error',
				});
			}

			const accessToken = createAccessToken(user.id);
			const refreshToken = createRefreshToken(user.id);

			dbOperations.updateRefreshToken(user.id, refreshToken, (err) => {
				if (err) {
					return res.status(500).json({
						message: 'Error saving refresh token!',
						type: 'error',
						error: err,
					});
				}

				sendRefreshToken(res, refreshToken);
				return res.json({
					message: 'Refreshed successfully! 🤗',
					type: 'success',
					accessToken,
				});
			});
		});
	} catch (error) {
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
			return res.json({
				message: 'You are logged in! 🤗',
				type: 'success',
				user: req.user,
			});
		}

		return res.status(500).json({
			message: 'You are not logged in! 😢',
			type: 'error',
		});
	} catch (error) {
		res.status(500).json({
			type: 'error',
			message: 'Error getting protected route!',
			error,
		});
	}
});

/* Validação e sanitização para send-password-reset-email */
const passwordResetValidation = [
	check('email').isEmail().normalizeEmail()
];

router.post('/send-password-reset-email', passwordResetValidation, async (req, res) => {
	try {
		const errors = validationResult(req);
		if (!errors.isEmpty()) {
			return res.status(400).json({
				message: 'Invalid email',
				type: 'error',
				errors: errors.array(),
			});
		}

		const { email } = req.body;

		dbOperations.findUserByEmail(email, async (err, user) => {
			if (err || !user) {
				return res.status(500).json({
					message: "User doesn't exist! 😢",
					type: 'error',
				});
			}

			const token = createPasswordResetToken(user);

			const url = createPasswordResetUrl(user.id, token);

			const mailOptions = passwordResetTemplate(user, url);
			transporter.sendMail(mailOptions, (err, info) => {
				console.log('Erro de envio de email:', err, 'Info:', info);
				if (err) {
					return res.status(500).json({
						message: 'Error sending email! 😢',
						type: 'error',
						error: err.message
					});
				}

				return res.json({
					message: 'Password reset link has been sent to your email! 📧',
					type: 'success',
				});
			});
		});
	} catch (error) {
		console.log('Error: ', error);
		res.status(500).json({
			type: 'error',
			message: 'Error sending email!',
			error,
		});
	}
});

/* Validação e sanitização para reset-password */
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
				return res.status(500).json({
					message: "User doesn't exist! 😢",
					type: 'error',
				});
			}

			let isValid;
			try {
				isValid = verify(token, process.env.VERIFY_EMAIL_TOKEN_SECRET);
			} catch (error) {
				return res.status(500).json({
					message: 'Invalid token! 😢',
					type: 'error',
				});
			}

			if (!isValid) {
				return res.status(500).json({
					message: 'Invalid token! 😢',
					type: 'error',
				});
			}

			const { salt, hash } = generateHash(newPassword);

			dbOperations.updatePassword(user.id, hash, salt, async (err) => {
				if (err) {
					return res.status(500).json({
						message: 'Error updating password!',
						type: 'error',
						error: err,
					});
				}

				const mailOptions = passwordResetConfirmationTemplate(user);
				transporter.sendMail(mailOptions, (err, info) => {
					if (err) {
						return res.status(500).json({
							message: 'Error sending email! 😢',
							type: 'error',
						});
					}

					return res.json({
						message: 'Email sent! 📧',
						type: 'success',
					});
				});
			});
		});
	} catch (error) {
		res.status(500).json({
			type: 'error',
			message: 'Error sending email!',
			error,
		});
	}
});

module.exports = router;