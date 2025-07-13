# loginauthapi

Este repositório contém uma API desenvolvida em Spring Boot, onde pratico a configuração do Spring Security. A API é projetada para demonstrar como implementar autenticação e autorização em aplicações Spring.

## Funcionalidades

- 🔒 Autenticação de usuários
- 🔑 Autorização baseada em roles
- 🛡️ Proteção de endpoints
- 🗄️ Exemplo de integração com um banco de dados em memória

## Tecnologias Utilizadas

- Java 21
- Spring Boot 3.5.3
- Spring Security
- JPA
- Banco de dados H2 (para testes)

## Como Executar a API

1. Clone o repositório:
   ```bash
   git clone https://github.com/fcursino/loginauthapi.git
   cd loginauthapi
2. Compile o projeto:
   ```bash
   ./mvnw clean install
3. Execute a aplicação:
   ```bash
   ./mvnw spring-boot:run
4. Acesse a API em http://localhost:8080.

## Demonstração

![Demonstração da API](https://github.com/fcursino/loginauthapi/raw/main/springsecurityemacao.gif)

