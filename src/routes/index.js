const express = require('express')
const router = express.Router()
const path = require('path');

router.get('/', function (_req, res) {
	res.sendFile(path.join(__dirname, '../', '../', 'public', 'index.html'))
})

module.exports = router
