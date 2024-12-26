using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.Filters;
using Swashbuckle.AspNetCore.SwaggerUI;
using System.Security.Claims;
using System.Text;
using WebAPI.CustomAuthorization;
using WebAPI.CustomResponse;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

// 添加Swagger服务
builder.Services.AddSwaggerGen(options =>
{
    options.UseInlineDefinitionsForEnums();
    // 开启加权小锁
    options.OperationFilter<AddResponseHeadersFilter>();
    options.OperationFilter<AppendAuthorizeToSummaryOperationFilter>();

    // 在header中添加token，传递到后台
    options.OperationFilter<SecurityRequirementsOperationFilter>();
    options.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
    {
        Type = SecuritySchemeType.OAuth2,
        Flows = new OpenApiOAuthFlows
        {
            Implicit = new OpenApiOAuthFlow
            {
                AuthorizationUrl = new Uri($"https://localhost:5001/connect/authorize"),
                Scopes = new Dictionary<string, string>
                                {
                                    {
                                        "test.api", "test.api"
                                    }
                                }
            }
        }
    });
});
builder.Services.AddSwaggerGenNewtonsoftSupport();


//读取配置文件
var symmetricKeyAsBase64 = "sdfsdfsrty45634kkhllghtdgdfss345t678fs";
var keyByteArray = Encoding.ASCII.GetBytes(symmetricKeyAsBase64);
var signingKey = new SymmetricSecurityKey(keyByteArray);
var Issuer = "Blog.Core";
var Audience = "wr";

var signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

// 如果要数据库动态绑定，这里先留个空，后边处理器里动态赋值
var permission = new List<PermissionItem>();

// 角色与接口的权限要求参数
var permissionRequirement = new PermissionRequirement(
    "/api/denied",// 拒绝授权的跳转地址（目前无用）
    permission,
    ClaimTypes.Role,// 基于角色的授权
    Issuer,//发行人
    Audience,// 听众
    signingCredentials,// 签名凭据
    expiration: TimeSpan.FromSeconds(60 * 60)//接口的过期时间
);
// 3、自定义复杂的策略授权
builder.Services.AddAuthorizationBuilder()
                           .AddPolicy("Permission", policy => policy.Requirements.Add(permissionRequirement));
builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
// 注入权限处理器
builder.Services.AddScoped<IAuthorizationHandler, PermissionHandler>();
builder.Services.AddSingleton(permissionRequirement);

builder.Services
    .AddAuthentication(o =>
    {
        o.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
        o.DefaultChallengeScheme = nameof(ApiResponseHandler);
        o.DefaultForbidScheme = nameof(ApiResponseHandler);
    })
    .AddJwtBearer(options =>
    {
        options.Authority = "https://localhost:5001";
        options.RequireHttpsMetadata = false;
        //options.Audience = "lc.erp.api";
        options.Audience = "test.api";
    })
    .AddScheme<AuthenticationSchemeOptions, ApiResponseHandler>(nameof(ApiResponseHandler), o => { });

builder.Services.AddControllers();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(options =>
    {
        //options.SwaggerEndpoint($"https://petstore.swagger.io/v2/swagger.json", $"LC.ERP.API pet");
        options.SwaggerEndpoint($"/swagger/v1/swagger.json", $"Test.API V1");
        options.DocExpansion(DocExpansion.None);
        ////options.OAuthClientId("lc-p-erp");
        options.OAuthClientId("testjs");
        options.ConfigObject.AdditionalItems.Add("persistAuthorization", "true");
        options.RoutePrefix = "";
    });
}
app.UseHttpsRedirection();

app.UseRouting();
// 身份认证中间件
app.UseAuthentication();
// 授权中间件
app.UseAuthorization();

app.MapControllers();

app.Run();
