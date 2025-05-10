# Executing:

## Windows
1. `npm install` or `npm i`
2. `npm run dev`
3. Ir em `public/index.html`
4. Abrir arquivo no navegador

### Comando Manuais
* Registro do usuário: `(Invoke-WebRequest -Uri http://localhost:8080/auth/signup -Method Post -Headers @{"Content-Type" = "application/json"} -Body '{"email":"gabriel.p.r.gabriel@gmail.com","password":"Senhazinha1234"}').Content | ConvertTo-Json`
* Login do usuário: `(Invoke-WebRequest -Uri http://localhost:8080/auth/signin -Method Post -Headers @{"Content-Type" = "application/json"} -Body '{"email":"gabriel.p.r.gabriel@gmail.com","password":"Senhazinha1234"}' -SessionVariable session).Content | ConvertTo-Json`
* Entrando na rota protegida: `(Invoke-WebRequest -Uri http://localhost:8080/auth/protected -Method Get -Headers @{"Authorization" = "Bearer <accesstoken>"}).Content | ConvertTo-Json`
* Refresh no token de acesso: `(Invoke-WebRequest -Uri http://localhost:8080/auth/refresh_token -Method Post -WebSession $session).Content | ConvertTo-Json`
* Enviando email para redefinição de senha: `(Invoke-WebRequest -Uri http://localhost:8080/auth/send-password-reset-email -Method Post -Headers @{"Content-Type" = "application/json"} -Body '{"email":"gabriel.p.r.gabriel@gmail.com"}').Content | ConvertTo-Json`
* Redefinindo senha: `(Invoke-WebRequest -Uri http://localhost:8080/auth/reset-password/<id>/<token> -Method Post -Headers @{"Content-Type" = "application/json"} -Body '{"newPassword":"NovaSenha1234"}').Content | ConvertTo-Json`
* Logout `(Invoke-WebRequest -Uri http://localhost:8080/auth/logout -Method Post).Content | ConvertTo-Json`

## Linux
1. `npm install` or `npm i`
2. `npm run dev`
3. Ir em `public/index.html`
4. Abrir arquivo no navegador

### Comando Manuais
* Registro do usuário: `curl -X POST http://localhost:8080/auth/signup -H "Content-Type: application/json" -d '{"email":"gabriel.p.r.gabriel@gmail.com","password":"Senhazinha1234"}'`
* Login do usuário: `curl -X POST http://localhost:8080/auth/signin -H "Content-Type: application/json" -b cookies.txt -c cookies.txt -d '{"email":"gabriel.p.r.gabriel@gmail.com","password":"Senhazinha1234"}'`
* Entrando na rota protegida: `curl -X GET http://localhost:8080/auth/protected -H "Authorization: Bearer <accesstoken>"`
* Refresh no token de acesso: `curl -X POST http://localhost:8080/auth/refresh_token -b cookies.txt -c cookies.txt`
* Enviando email para redefinição de senha: `curl -X POST http://localhost:8080/auth/send-password-reset-email -H "Content-Type: application/json" -d '{"email":"gabriel.p.r.gabriel@gmail.com"}'`
* Redefinindo senha: `curl -X POST http://localhost:8080/auth/reset-password/<id>/<token> -H "Content-Type: application/json" -d '{"newPassword":"NovaSenha1234"}'`
* Logout: `curl -X POST http://localhost:8080/auth/logout`

