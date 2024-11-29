using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text.Json;

namespace MyApp.Namespace
{
    // 未使用 HttpClientFactory Demo
    //public class CallApiModel : PageModel
    //{
    //    public string Json = string.Empty;
    //    public async Task OnGet()
    //    {
    //        // 未自动刷新Token的写法
    //        //var accessToken = await HttpContext.GetTokenAsync("access_token");
    //        //var client = new HttpClient();
    //        //client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
    //        //var content = await client.GetStringAsync("https://localhost:6001/identity");

    //        //var parsed = JsonDocument.Parse(content);
    //        //var formatted = JsonSerializer.Serialize(parsed, new JsonSerializerOptions { WriteIndented = true });

    //        //Json = formatted;

    //        // 自动刷新Token 的写法
    //        var tokenInfo = await HttpContext.GetUserAccessTokenAsync();
    //        var client = new HttpClient();
    //        client.SetBearerToken(tokenInfo.AccessToken!);

    //        var content = await client.GetStringAsync("https://localhost:6001/identity");

    //        var parsed = JsonDocument.Parse(content);
    //        var formatted = JsonSerializer.Serialize(parsed, new JsonSerializerOptions { WriteIndented = true });

    //        Json = formatted;
    //    }
    //}

    // 使用 HttpClientFactory  Demo
    // 注意：需要在Program里对 HttpClientFactory 进行注册
    public class CallApiModel(IHttpClientFactory httpClientFactory) : PageModel
    {
        public string Json = string.Empty;

        public async Task OnGet()
        {
            var client = httpClientFactory.CreateClient("apiClient");

            var content = await client.GetStringAsync("https://localhost:6001/identity");

            var parsed = JsonDocument.Parse(content);
            var formatted = JsonSerializer.Serialize(parsed, new JsonSerializerOptions { WriteIndented = true });

            Json = formatted;
        }
    }
}
