using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using System.Text.Encodings.Web;

namespace WebAPI.CustomResponse;

public class ApiResponseHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{

    public ApiResponseHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
    {

    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        throw new NotImplementedException();
    }

    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.ContentType = "application/json";
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        await Response.WriteAsync(JsonConvert.SerializeObject((new ApiResponse(StatusCode.CODE401)).MessageModel));
    }

    protected override async Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        Response.ContentType = "application/json";

        Response.StatusCode = StatusCodes.Status403Forbidden;
        await Response.WriteAsync(JsonConvert.SerializeObject((new ApiResponse(StatusCode.CODE403)).MessageModel));

    }
}

public class ApiResponse
{
    public int Status { get; set; } = 200;
    public string Value { get; set; } = "";
    public MessageModel<string> MessageModel = new MessageModel<string>() { };

    public ApiResponse(StatusCode apiCode, string msg = null)
    {
        switch (apiCode)
        {
            case StatusCode.CODE401:
                {
                    Status = 401;
                    Value = msg ?? "很抱歉，您无权访问该接口，请确保已经登录!";
                }
                break;
            case StatusCode.CODE403:
                {
                    Status = 403;
                    Value = msg ?? "很抱歉，您的访问权限等级不够，联系管理员!";
                }
                break;
            case StatusCode.CODE404:
                {
                    Status = 404;
                    Value = "资源不存在!";
                }
                break;
            case StatusCode.CODE500:
                {
                    Status = 500;
                    Value = msg;
                }
                break;
        }

        MessageModel = new MessageModel<string>()
        {
            status = Status,
            msg = Value,
            success = apiCode == StatusCode.CODE200
        };
    }
}

public enum StatusCode
{
    CODE200,
    CODE401,
    CODE403,
    CODE404,
    CODE500
}

/// <summary>
/// 通用返回信息类
/// </summary>
public class MessageModel<T>
{
    /// <summary>
    /// 状态码
    /// </summary>
    public int status { get; set; } = 200;
    /// <summary>
    /// 操作是否成功
    /// </summary>
    public bool success { get; set; } = false;
    /// <summary>
    /// 返回信息
    /// </summary>
    public string msg { get; set; } = "";
    /// <summary>
    /// 开发者信息
    /// </summary>
    public string msgDev { get; set; }
    /// <summary>
    /// 返回数据集合
    /// </summary>
    public T response { get; set; }

    /// <summary>
    /// 返回成功
    /// </summary>
    /// <param name="msg">消息</param>
    /// <returns></returns>
    public static MessageModel<T> Success(string msg)
    {
        return Message(true, msg, default);
    }
    /// <summary>
    /// 返回成功
    /// </summary>
    /// <param name="msg">消息</param>
    /// <param name="response">数据</param>
    /// <returns></returns>
    public static MessageModel<T> Success(string msg, T response)
    {
        return Message(true, msg, response);
    }
    /// <summary>
    /// 返回失败
    /// </summary>
    /// <param name="msg">消息</param>
    /// <returns></returns>
    public static MessageModel<T> Fail(string msg)
    {
        return Message(false, msg, default);
    }
    /// <summary>
    /// 返回失败
    /// </summary>
    /// <param name="msg">消息</param>
    /// <param name="response">数据</param>
    /// <returns></returns>
    public static MessageModel<T> Fail(string msg, T response)
    {
        return Message(false, msg, response);
    }
    /// <summary>
    /// 返回消息
    /// </summary>
    /// <param name="success">失败/成功</param>
    /// <param name="msg">消息</param>
    /// <param name="response">数据</param>
    /// <returns></returns>
    public static MessageModel<T> Message(bool success, string msg, T response)
    {
        return new MessageModel<T>() { msg = msg, response = response, success = success };
    }
}

public class MessageModel
{
    /// <summary>
    /// 状态码
    /// </summary>
    public int status { get; set; } = 200;
    /// <summary>
    /// 操作是否成功
    /// </summary>
    public bool success { get; set; } = false;
    /// <summary>
    /// 返回信息
    /// </summary>
    public string msg { get; set; } = "";
    /// <summary>
    /// 返回数据集合
    /// </summary>
    public object response { get; set; }
}