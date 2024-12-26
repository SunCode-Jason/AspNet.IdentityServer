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

// ���Swagger����
builder.Services.AddSwaggerGen(options =>
{
    options.UseInlineDefinitionsForEnums();
    // ������ȨС��
    options.OperationFilter<AddResponseHeadersFilter>();
    options.OperationFilter<AppendAuthorizeToSummaryOperationFilter>();

    // ��header�����token�����ݵ���̨
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


//��ȡ�����ļ�
var symmetricKeyAsBase64 = "sdfsdfsrty45634kkhllghtdgdfss345t678fs";
var keyByteArray = Encoding.ASCII.GetBytes(symmetricKeyAsBase64);
var signingKey = new SymmetricSecurityKey(keyByteArray);
var Issuer = "Blog.Core";
var Audience = "wr";

var signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

// ���Ҫ���ݿ⶯̬�󶨣������������գ���ߴ������ﶯ̬��ֵ
var permission = new List<PermissionItem>();

// ��ɫ��ӿڵ�Ȩ��Ҫ�����
var permissionRequirement = new PermissionRequirement(
    "/api/denied",// �ܾ���Ȩ����ת��ַ��Ŀǰ���ã�
    permission,
    ClaimTypes.Role,// ���ڽ�ɫ����Ȩ
    Issuer,//������
    Audience,// ����
    signingCredentials,// ǩ��ƾ��
    expiration: TimeSpan.FromSeconds(60 * 60)//�ӿڵĹ���ʱ��
);
// 3���Զ��帴�ӵĲ�����Ȩ
builder.Services.AddAuthorizationBuilder()
                           .AddPolicy("Permission", policy => policy.Requirements.Add(permissionRequirement));
builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
// ע��Ȩ�޴�����
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
// �����֤�м��
app.UseAuthentication();
// ��Ȩ�м��
app.UseAuthorization();

app.MapControllers();

app.Run();
