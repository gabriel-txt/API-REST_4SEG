const { sign } = require('jsonwebtoken')

// Cadastrando o access token
const createAccessToken = (id) => {
	return sign({ id }, process.env.ACCESS_TOKEN_SECRET, {
		expiresIn: 15 * 60,
	})
}

// Cadastrando o refresh token
const createRefreshToken = (id) => {
	return sign({ id }, process.env.REFRESH_TOKEN_SECRET, {
		expiresIn: '90d',
	})
}

// Enviando o access token para o cliente
const sendAccessToken = (_req, res, accesstoken) => {
	res.json({
		accesstoken,
		message: 'Sign in Successful 🥳',
		type: 'success',
	})
}

// Enviando o access token para o cliente como cookie
const sendRefreshToken = (res, refreshtoken) => {
	res.cookie('refreshtoken', refreshtoken, {
		httpOnly: true,
	})
}

// Criando um token para password reset
const createPasswordResetToken = ({ id, email }) => {
	return sign({ id, email }, process.env.VERIFY_EMAIL_TOKEN_SECRET, {
	  expiresIn: 15 * 60,
	});
};

module.exports = {
	createAccessToken,
	createRefreshToken,
	sendAccessToken,
	sendRefreshToken,
	createPasswordResetToken,
}
