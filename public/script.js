document.addEventListener('DOMContentLoaded', () => {
    const signupForm = document.getElementById('signup-form');
    const signinForm = document.getElementById('signin-form');
    const verify2FAForm = document.getElementById('verify-2fa-form');
    const signupMessage = document.getElementById('signup-message');
    const signinMessage = document.getElementById('signin-message');
    const verify2FAMessage = document.getElementById('verify-2fa-message');
    const verify2FALink = document.getElementById('verify-2fa-link');
    const protectedLink = document.getElementById('protected-link');
    const logoutLink = document.getElementById('logout-link');
    let session = null;
    let userId = null;

    // Mostrar seção com base no hash da URL
    function showSection(sectionId) {
        console.log('Mostrando seção:', sectionId);
        document.querySelectorAll('section').forEach(section => {
            section.classList.remove('active');
            section.style.display = 'none';
        });
        const section = document.getElementById(sectionId);
        if (section) {
            section.classList.add('active');
            section.style.display = 'block';
            console.log('Seção encontrada e exibida:', sectionId);
        } else {
            document.getElementById('signin').classList.add('active');
            document.getElementById('signin').style.display = 'block';
            console.log('Seção não encontrada, fallback para signin');
        }
    }

    // Adicionar evento de clique direto aos links para garantir navegação
    document.querySelectorAll('nav a').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const href = link.getAttribute('href');
            if (href.startsWith('#')) {
                location.hash = href.substring(1);
                showSection(href.substring(1));
            }
        });
    });

    // Lidar com mudanças de hash
    window.addEventListener('hashchange', () => {
        const sectionId = location.hash.substring(1) || 'signin';
        console.log('Hash mudou para:', sectionId);
        showSection(sectionId);
    });

    // Exibir seção inicial ao carregar a página
    showSection(location.hash.substring(1) || 'signin');

    // Função para exibir mensagem temporária
    function displayMessage(element, message, duration = 15000) {
        console.log('Exibindo mensagem:', message);
        element.textContent = message;
        element.style.display = 'block';
        setTimeout(() => {
            element.textContent = '';
            element.style.display = 'none';
        }, duration);
    }

    // Função para processar requisições fetch com erro robusto
    async function handleFetch(url, options) {
        try {
            const response = await fetch(url, options);
            console.log('Status da resposta:', response.status, 'OK:', response.ok);
            console.log('Headers da resposta:', [...response.headers.entries()]);
            const text = await response.text();
            console.log('Corpo da resposta:', text);
            let result;
            try {
                result = JSON.parse(text);
            } catch (parseError) {
                throw new Error('Resposta inválida do servidor: ' + parseError.message);
            }
            console.log('Resposta do servidor:', result);
            return { result, response };
        } catch (error) {
            console.error('Erro na requisição:', error.message);
            throw new Error('Falha na comunicação com o servidor: ' + error.message);
        }
    }

    // Registro
    signupForm.addEventListener('submit', (e) => {
        e.preventDefault();
        console.log('Formulário de registro enviado - Previndo recarregamento');
        const data = {
            username: document.getElementById('username').value,
            password: document.getElementById('password').value,
            nome: document.getElementById('nome').value,
            email: document.getElementById('email').value,
            perfil: "admin"
        };
        handleFetch('http://localhost:8080/auth/signup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
            credentials: 'include'
        })
            .then(({ result }) => {
                console.log('Enviando requisição para:', 'http://localhost:8080/auth/signup', 'com dados:', data);
                displayMessage(signupMessage, result.message);
                if (result.type === 'success') {
                    setTimeout(() => {
                        console.log('Redirecionando para signin após registro');
                        location.hash = '#signin';
                        showSection('signin');
                    }, 2000);
                } else {
                    displayMessage(signupMessage, result.message || 'Erro ao registrar! Detalhes: ' + JSON.stringify(result));
                }
            })
            .catch(error => {
                console.error('Erro ao registrar:', error.message);
                displayMessage(signupMessage, 'Erro ao registrar! Detalhes: ' + error.message);
            });
    });

    // Login
    signinForm.addEventListener('submit', (e) => {
        e.preventDefault();
        console.log('Formulário de login enviado - Previndo recarregamento');
        const data = {
            username: document.getElementById('login-username').value,
            password: document.getElementById('login-password').value,
            captcha: document.getElementById('captcha').value || ''
        };
        handleFetch('http://localhost:8080/auth/signin', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
            credentials: 'include'
        })
            .then(({ result, response }) => {
                console.log('Enviando requisição para:', 'http://localhost:8080/auth/signin', 'com dados:', data);
                displayMessage(signinMessage, result.message);
                session = response.headers.get('Set-Cookie') || session;
                console.log('Cookie de sessão após login:', session);
                if (result.requires2FA) {
                    console.log('2FA necessário, userId:', result.userId);
                    userId = result.userId;
                    const userIdField = document.getElementById('user-id');
                    if (userIdField) {
                        userIdField.value = userId;
                        console.log('User ID preenchido:', userId);
                    } else {
                        console.error('Campo user-id não encontrado');
                    }
                    document.getElementById('captcha-label').style.display = 'none';
                    document.getElementById('captcha').style.display = 'none';
                    verify2FALink.style.display = 'block';
                    console.log('Exibindo link de verificação 2FA');
                    setTimeout(() => {
                        console.log('Redirecionando para verify-2fa');
                        location.hash = '#verify-2fa';
                        showSection('verify-2fa');
                    }, 2000);
                } else if (result.requiresCaptcha) {
                    console.log('CAPTCHA necessário');
                    document.getElementById('captcha-label').style.display = 'block';
                    document.getElementById('captcha').style.display = 'block';
                } else if (result.type === 'success') {
                    console.log('Login bem-sucedido, indo para área protegida');
                    protectedLink.style.display = 'block';
                    logoutLink.style.display = 'block';
                    setTimeout(() => {
                        console.log('Redirecionando para protected');
                        location.hash = '#protected';
                        showSection('protected');
                        fetchProtectedData();
                    }, 2000);
                } else {
                    console.log('Resposta inesperada:', result);
                    displayMessage(signinMessage, 'Resposta inesperada do servidor: ' + JSON.stringify(result));
                }
            })
            .catch(error => {
                console.error('Erro ao fazer login:', error.message);
                displayMessage(signinMessage, 'Erro ao fazer login! Detalhes: ' + error.message);
            });
    });

    // Verificar 2FA
    verify2FAForm.addEventListener('submit', (e) => {
        e.preventDefault();
        console.log('Formulário de verificação 2FA enviado - Previndo recarregamento');
        const data = {
            userId: document.getElementById('user-id').value,
            code: document.getElementById('two-factor-code').value
        };
        handleFetch('http://localhost:8080/auth/verify-2fa', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
            credentials: 'include'
        })
            .then(({ result, response }) => {
                console.log('Enviando requisição para:', 'http://localhost:8080/auth/verify-2fa', 'com dados:', data);
                displayMessage(verify2FAMessage, result.message);
                session = response.headers.get('Set-Cookie') || session;
                console.log('Cookie de sessão após 2FA:', session);
                if (result.type === 'success') {
                    protectedLink.style.display = 'block';
                    logoutLink.style.display = 'block';
                    setTimeout(() => {
                        console.log('Redirecionando para protected após 2FA');
                        location.hash = '#protected';
                        showSection('protected');
                        fetchProtectedData();
                    }, 2000);
                }
            })
            .catch(error => {
                console.error('Erro ao verificar 2FA:', error.message);
                displayMessage(verify2FAMessage, 'Erro ao verificar 2FA! Detalhes: ' + error.message);
            });
    });

    // Logout
    logoutLink.addEventListener('click', async (e) => {
        e.preventDefault();
        try {
            console.log('Enviando requisição para logout');
            await fetch('http://localhost:8080/auth/logout', {
                method: 'POST',
                headers: { 'Cookie': session },
                credentials: 'include'
            });
            session = null;
            protectedLink.style.display = 'none';
            logoutLink.style.display = 'none';
            verify2FALink.style.display = 'none';
            location.hash = '#signin';
            showSection('signin');
        } catch (error) {
            console.error('Erro ao fazer logout:', error);
        }
    });

    // Área Protegida
    protectedLink.addEventListener('click', async (e) => {
        e.preventDefault();
        try {
            console.log('Acessando área protegida');
            fetchProtectedData();
        } catch (error) {
            console.error('Erro ao acessar área protegida:', error);
        }
    });

    // Função para buscar e preencher dados da área protegida
    async function fetchProtectedData() {
        try {
            console.log('Buscando dados protegidos com cookie:', session);
            const response = await fetch('http://localhost:8080/auth/protected', {
                method: 'GET',
                headers: {
                    'Cookie': session || '',
                    'Content-Type': 'application/json'
                },
                credentials: 'include'
            });
            const result = await response.json();
            console.log('Dados da área protegida:', result);
            document.getElementById('protected-message').textContent = result.message || 'Bem-vindo! Você está logado.';
            if (result.user) {
                document.getElementById('user-name').textContent = result.user.name || '[Nome Não Encontrado]';
                document.getElementById('user-email').textContent = result.user.email || '[Email Não Encontrado]';
            } else {
                console.log('Nenhum dado de usuário retornado');
                document.getElementById('user-name').textContent = '[Nome Não Encontrado]';
                document.getElementById('user-email').textContent = '[Email Não Encontrado]';
            }
        } catch (error) {
            console.error('Erro ao carregar dados protegidos:', error);
            document.getElementById('protected-message').textContent = 'Erro ao carregar dados: ' + error.message;
            document.getElementById('user-name').textContent = '[Nome Não Encontrado]';
            document.getElementById('user-email').textContent = '[Email Não Encontrado]';
        }
    }
});