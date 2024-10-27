using ArgusBackend.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddHttpClient<IVirusTotalService, VirusTotalService>();

//CORS
builder.Services.AddCors(options =>
{
options.AddPolicy("AllowBlazorApp",
    policy =>
    {
        policy.WithOrigins("https://localhost:7041")
        .AllowAnyMethod()
        .AllowAnyHeader();
    });
});

var app = builder.Build();
app.UseCors("AllowBlazorApp");

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
