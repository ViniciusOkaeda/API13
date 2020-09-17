# API13
api simples com autenticação de login usando JWT

## PREPARATÓRIO

## Scripts

### Tarde

[Nyous_DDL.sql](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/039a7914-5fe4-466b-b087-74b1fd39ef08/Nyous_DDL.sql)

[Nyous_DML.sql](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/c9c6bea7-7397-4949-a4b7-2cab101f7970/Nyous_DML.sql)

[Nyous_DQL.sql](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/8bb46287-3c90-4bf3-8297-273df11faee7/Nyous_DQL.sql)

- [x]  Importar scripts do banco
- [x]  Criar uma solução de API
- [x]  Adicionar pacotes:

    ![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/91d32076-c237-4d54-9bdf-a9021cd7bdd2/Untitled.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/91d32076-c237-4d54-9bdf-a9021cd7bdd2/Untitled.png)

- [x]  Criar os Domains pelo EFCore - Database First

    ```csharp
    Scaffold-DbContext "Data Source=.\SqlExpress; Initial Catalog= NyousTarde; User Id=sa; Password=sa132" Microsoft.EntityFrameworkCore.SqlServer -OutputDir Domains -ContextDir Contexts -Context NyousContext
    ```

    ![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/3cd8512a-f618-4574-b114-74964d194ed4/Untitled.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/3cd8512a-f618-4574-b114-74964d194ed4/Untitled.png)

    ## JWT

    - [x]  Instalar pacote JWT:

    ![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/b2526b55-b922-4ba1-bcd3-7b109715255b/Untitled.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/b2526b55-b922-4ba1-bcd3-7b109715255b/Untitled.png)

    - [x]  Adicionamos em nosso appsettings.json :

        ```csharp
        "Jwt": {
            "Key": "ThisIsMyNyousSecretKey",
            "Issuer": "nyous.com.br"
         },
        ```

    - [x]  Adicionar a configuração do nosso Serviço de autenticação:

        ```csharp
        // JWT
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)  
        .AddJwtBearer(options =>  
        {  
            options.TokenValidationParameters = new TokenValidationParameters  
            {  
                ValidateIssuer = true,  
                ValidateAudience = true,  
                ValidateLifetime = true,  
                ValidateIssuerSigningKey = true,  
                ValidIssuer = Configuration["Jwt:Issuer"],  
                ValidAudience = Configuration["Jwt:Issuer"],  
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["Jwt:Key"]))  
            };  
        });
        ```

    - [x]  Importar as libs faltantes com Control + ponto ou:

        ```csharp
        using Microsoft.IdentityModel.Tokens;
        using Microsoft.AspNetCore.Authentication.JwtBearer;
        using System.Text;
        ```

    - [x]  Em Startup.cs , no método Configure , usamos efetivamente a autenticação:
        - **nota**: se não colocar **em cima** de *app.UseAuthorization()* , não funcionará corretamente

        ```csharp
        app.UseAuthentication();
        ```

    - [x]  Criamos o Controller *Login*:

        ![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/f3afc5de-18fe-47df-97be-5a1a97147d58/Untitled.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/f3afc5de-18fe-47df-97be-5a1a97147d58/Untitled.png)

        ![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/8a4e20cd-e134-44c5-8b52-e1b58914e139/Untitled.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/8a4e20cd-e134-44c5-8b52-e1b58914e139/Untitled.png)

    - [x]  Chamamos nosso contexto lá dentro:

        ```csharp
        // Chamamos nosso contexto do banco
        NyousContext _context = new NyousContext();
        ```

    - [x]  Definimos um método construtor para pegar as informações de appsettings.json:

        ```csharp
        // Definimos uma variável para percorrer nossos métodos com as configurações obtidas no appsettings.json
        private IConfiguration _config;  

        // Definimos um método construtor para poder passar essas configs
        public LoginController(IConfiguration config)  
        {  
            _config = config;  
        }
        ```

    - [x]  Criamos um método para validar nosso usuário da aplicação:

        ```csharp
        private Usuario AuthenticateUser(Usuario login)
        {
            return _context.Usuario.Include(a => a.IdAcessoNavigation).FirstOrDefault(u => u.Email == login.Email && u.Senha == login.Senha);
        }
        ```

    - [x]  Criamos um método que vai gerar nosso Token:

        ```csharp
        // Criamos nosso método que vai gerar nosso Token
        private string GenerateJSONWebToken(Usuario userInfo)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            // Definimos nossas Claims (dados da sessão) para poderem ser capturadas
            // a qualquer momento enquanto o Token for ativo
            var claims = new[] {
                new Claim(JwtRegisteredClaimNames.NameId, userInfo.Nome),
                new Claim(JwtRegisteredClaimNames.Email, userInfo.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        				new Claim(ClaimTypes.Role, userInfo.IdAcessoNavigation.Tipo)
            };

            // Configuramos nosso Token e seu tempo de vida
            var token = new JwtSecurityToken
                (
                    _config["Jwt:Issuer"],
                    _config["Jwt:Issuer"],
                    claims,
                    expires: DateTime.Now.AddMinutes(120),
                    signingCredentials: credentials
                );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        ```

    - [x]  Criamos o endpoint da API responsável por consumir os métodos de autenticação:

        ```csharp
        // Usamos a anotação "AllowAnonymous" para 
        // ignorar a autenticação neste método, já que é ele quem fará isso
        [AllowAnonymous]
        [HttpPost]
        public IActionResult Login([FromBody] Usuario login)
        {
            // Definimos logo de cara como não autorizado
            IActionResult response = Unauthorized();

            // Autenticamos o usuário da API
            var user = AuthenticateUser(login);
            if (user != null)
            {
                var tokenString = GenerateJSONWebToken(user);
                response = Ok(new { token = tokenString });
            }

            return response;
        }
        ```

    - [x]  Testamos se está sendo gerado nosso Token pelo Postman, no método POST

        Pela URL :

        [https://localhost:<porta>/api/login](https://localhost:5001/api/login)

        E com os seguintes parâmetros pela RAW :

        ```csharp
        {
            "email": "paulo@senai.com.br",
            "senha": "1234567890",
        }
        ```

    - [x]  Se estiver tudo certo ele deve retornar isto no Postman:

        ![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/430e28cd-4d12-42f5-bea2-0a8959954aa3/Untitled.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/430e28cd-4d12-42f5-bea2-0a8959954aa3/Untitled.png)

        - [x]  Após confirmar, vamos até [https://jwt.io/](https://jwt.io/)
        - [x]  Colamos nosso Token lá e em Payload devemos ter os seguintes dados:

            ![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/571a7998-5930-46bb-9a33-1ea5b172d4fd/Untitled.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/571a7998-5930-46bb-9a33-1ea5b172d4fd/Untitled.png)

    Pronto! Agora é só utilizar a anotação em cima de cada método que desejar bloquear:

    ***[Authorize]***

    em baixo da anotação REST de cada método que desejar colocar autenticação!

    No Postman devemos gerar um token pela rota de login e nos demais endpoints devemos adicionar o token gerado na aba:

    ***Authorization***

    escolhendo a opção:

    ***Baerer Token***

    ### Testando em um Controller

    - [x]  Para testarmos, criamos o controller para "Categoria":

        ![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/a1dba6a0-2922-4e59-a9b4-b7f5b8888d55/Untitled.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/a1dba6a0-2922-4e59-a9b4-b7f5b8888d55/Untitled.png)

        ![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/e8cca272-5dfc-455f-88e2-1573b05cd009/Untitled.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/e8cca272-5dfc-455f-88e2-1573b05cd009/Untitled.png)

    ### IMPORTANTE para não gerar erros:

    - [x]  Depois de gerar a classe automaticamente trocamos este método construtor:

        ```csharp
        private readonly NyousContext _context;

        public CategoriasController(NyousContext context)
        {
            _context = context;
        }
        ```

    - [x]  Por este tipo de instância:

        ```csharp
        private NyousContext _context = new NyousContext();
        ```

    ### Continuando...

    - [x]  Testamos no postman:

        ![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/dff0d5bb-661d-416d-94a9-ad6efabf9b62/Untitled.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/dff0d5bb-661d-416d-94a9-ad6efabf9b62/Untitled.png)

    - [x]  Para testar o JWT colocamos o Authotrize nos métodos que desejamos bloquear, ou na classe toda caso ela necessite do mesmo bloqueio:

        ![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/6d69d133-99a0-4cbf-a958-eebb45eced85/Untitled.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/6d69d133-99a0-4cbf-a958-eebb45eced85/Untitled.png)

    Se rodarmos a aplicação sem nenhum token ativo, ele deve retornar erro 401 (Não autorizado):

    ![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/db473ae2-46e4-42cc-bd82-136732e06238/Untitled.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/db473ae2-46e4-42cc-bd82-136732e06238/Untitled.png)

    - [x]  Com a API rodando, vamos para o endpoint de login e geramos um novo Token

        ![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/3f1158c6-91e8-49bc-b9d1-0f25f3f21c0f/Untitled.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/3f1158c6-91e8-49bc-b9d1-0f25f3f21c0f/Untitled.png)

    - [x]  Copiamos o token e colamos na aba

        ![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/cedbd6ba-e7df-4caa-8bf1-719f97a53f19/Untitled.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/cedbd6ba-e7df-4caa-8bf1-719f97a53f19/Untitled.png)

    ### ADICIONANDO PERMISSÃO PARA TIPOS DE USUÁRIOS

    - [x]  Basta colocar as permissões, separadas por virgula:

        ```csharp
        [Authorize(Roles = "Padrao,Administrador")]
        ```

    ## Links de apoio

    [https://jwt.io/](https://jwt.io/)
