using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text.Json;

namespace MyApp.Namespace
{
    // δʹ�� HttpClientFactory Demo
    //public class CallApiModel : PageModel
    //{
    //    public string Json = string.Empty;
    //    public async Task OnGet()
    //    {
    //        // δ�Զ�ˢ��Token��д��
    //        //var accessToken = await HttpContext.GetTokenAsync("access_token");
    //        //var client = new HttpClient();
    //        //client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
    //        //var content = await client.GetStringAsync("https://localhost:6001/identity");

    //        //var parsed = JsonDocument.Parse(content);
    //        //var formatted = JsonSerializer.Serialize(parsed, new JsonSerializerOptions { WriteIndented = true });

    //        //Json = formatted;

    //        // �Զ�ˢ��Token ��д��
    //        var tokenInfo = await HttpContext.GetUserAccessTokenAsync();
    //        var client = new HttpClient();
    //        client.SetBearerToken(tokenInfo.AccessToken!);

    //        var content = await client.GetStringAsync("https://localhost:6001/identity");

    //        var parsed = JsonDocument.Parse(content);
    //        var formatted = JsonSerializer.Serialize(parsed, new JsonSerializerOptions { WriteIndented = true });

    //        Json = formatted;
    //    }
    //}

    // ʹ�� HttpClientFactory  Demo
    // ע�⣺��Ҫ��Program��� HttpClientFactory ����ע��
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
