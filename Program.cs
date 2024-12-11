using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

DotNetEnv.Env.Load();

var app = builder.Build();

app.MapPost("/encrypt", async (HttpContext context) =>
{

    // Validate that the body is not empty
    if (context.Request.ContentLength == 0)
    {
        return Results.BadRequest("The request body cannot be empty.");
    }

    JsonElement json;
    try
    {
        json = await context.Request.ReadFromJsonAsync<JsonElement>();
    }
    catch (JsonException)
    {
        return Results.BadRequest("Malformed JSON in the request body.");
    }

    if (json.ValueKind == JsonValueKind.Undefined)
    {
        return Results.BadRequest("Input JSON is required.");
    }

    var jsonString = json.ToString();
    if (string.IsNullOrEmpty(jsonString))
    {
        return Results.BadRequest("Failed to serialize input JSON.");
    }

    Console.WriteLine($"Input JSON: {jsonString}");

    var (key, iv) = EncryptionHelper.GetEncryptionSettings();

    try
    {
        var encryptedData = EncryptionHelper.EncryptData(jsonString, key, iv);
        Console.WriteLine($"Encrypted Data: {encryptedData}");
        return Results.Ok(new { CipherText = encryptedData });
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Encryption failed: {ex.Message}");
        return Results.Problem("An error occurred during encryption.");
    }
});


app.MapPost("/decrypt", async (HttpContext context) =>
{
    // Validate that the body is not empty
    if (context.Request.ContentLength == 0)
    {
        return Results.BadRequest("The request body cannot be empty.");
    }

    string? cipherText;
    
    try
    {
        cipherText = await context.Request.ReadFromJsonAsync<string>();
    }
    catch (JsonException)
    {
        return Results.BadRequest("Malformed JSON in the request body.");
    }

    if (string.IsNullOrEmpty(cipherText))
    {
        return Results.BadRequest("Ciphertext is required.");
    }

    var (key, iv) = EncryptionHelper.GetEncryptionSettings();

    try
    {
        var decryptedData = EncryptionHelper.DecryptData(cipherText, key, iv);
        var jsonData = JsonSerializer.Deserialize<JsonElement>(decryptedData);

        return Results.Ok(new { DecryptedData = jsonData });
    }
    catch (FormatException)
    {
        return Results.BadRequest("The provided ciphertext is not a valid Base64 string.");
    }
    catch (JsonException)
    {
        return Results.BadRequest("Decrypted data is not valid JSON.");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Decryption failed: {ex.Message}");
        return Results.Problem("An error occurred during decryption.");
    }
});

app.Run();

