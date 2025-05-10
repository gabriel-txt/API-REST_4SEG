# Executing:

## Windows
1. `npm install` or `npm i`
2. `npm run dev`

### Comando Manuais
3. Registro do usuário: `(Invoke-WebRequest -Uri http://localhost:8080/auth/signup -Method Post -Headers @{"Content-Type" = "application/json"} -Body '{"email":"gabriel.p.r.gabriel@gmail.com","password":"Senhazinha1234"}').Content | ConvertTo-Json`
4. Login do usuário: `(Invoke-WebRequest -Uri http://localhost:8080/auth/signin -Method Post -Headers @{"Content-Type" = "application/json"} -Body '{"email":"gabriel.p.r.gabriel@gmail.com","password":"Senhazinha1234"}' -SessionVariable session).Content | ConvertTo-Json`
5. Entrando na rota protegida: `(Invoke-WebRequest -Uri http://localhost:8080/auth/protected -Method Get -Headers @{"Authorization" = "Bearer <accesstoken>"}).Content | ConvertTo-Json`
6. Refresh no token de acesso: `(Invoke-WebRequest -Uri http://localhost:8080/auth/refresh_token -Method Post -WebSession $session).Content | ConvertTo-Json`
7. Enviando email para redefinição de senha: `(Invoke-WebRequest -Uri http://localhost:8080/auth/send-password-reset-email -Method Post -Headers @{"Content-Type" = "application/json"} -Body '{"email":"gabriel.p.r.gabriel@gmail.com"}').Content | ConvertTo-Json`
8. Redefinindo senha: `(Invoke-WebRequest -Uri http://localhost:8080/auth/reset-password/<id>/<token> -Method Post -Headers @{"Content-Type" = "application/json"} -Body '{"newPassword":"NovaSenha1234"}').Content | ConvertTo-Json`
9. Logout `(Invoke-WebRequest -Uri http://localhost:8080/auth/logout -Method Post).Content | ConvertTo-Json`

## Linux
1. `npm install` or `npm i`
2. `npm run dev`

### Comando Manuais
3. Registro do usuário: `curl -X POST http://localhost:8080/auth/signup -H "Content-Type: application/json" -d '{"email":"gabriel.p.r.gabriel@gmail.com","password":"Senhazinha1234"}'`
4. Login do usuário: `curl -X POST http://localhost:8080/auth/signin -H "Content-Type: application/json" -b cookies.txt -c cookies.txt -d '{"email":"gabriel.p.r.gabriel@gmail.com","password":"Senhazinha1234"}'`
5. Entrando na rota protegida: `curl -X GET http://localhost:8080/auth/protected -H "Authorization: Bearer <accesstoken>"`
6. Refresh no token de acesso: `curl -X POST http://localhost:8080/auth/refresh_token -b cookies.txt -c cookies.txt`
7. Enviando email para redefinição de senha: `curl -X POST http://localhost:8080/auth/send-password-reset-email -H "Content-Type: application/json" -d '{"email":"gabriel.p.r.gabriel@gmail.com"}'`
8. Redefinindo senha: `curl -X POST http://localhost:8080/auth/reset-password/<id>/<token> -H "Content-Type: application/json" -d '{"newPassword":"NovaSenha1234"}'`
9. Logout: `curl -X POST http://localhost:8080/auth/logout`

