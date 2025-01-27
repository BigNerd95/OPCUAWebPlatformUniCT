﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Microsoft.IdentityModel.Tokens;
using WebPlatform.Auth;
using WebPlatform.Models.OptionsModels;
using WebPlatform.OPCUALayer;
using WebPlatform.MVCBugFix;

namespace WebPlatform
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            //Add service related to Jwt Authentication
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options => 
            {
                options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                {
                    ValidateIssuer = false, //true,
                    ValidateAudience = false, //true,
                    ValidateLifetime = false, //true,
                    ValidateIssuerSigningKey = false, //true,
                    ValidIssuer = Configuration["JwtOptions:Issuer"],
                    ValidAudience = Configuration["JwtOptions:Audience"],
                    IssuerSigningKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(Configuration["JwtOptions:SecurityKey"]))
                };
            });

            //Add service related to IOptions feature in Controllers
            services.AddOptions();
            services.Configure<JwtOptions>(Configuration.GetSection("JwtOptions"));
            services.Configure<OPCUAServersOptions>(Configuration.GetSection("OPCUAServersOptions"));

            //services.AddMvc();
            services.AddMvc(options => options.EnableEndpointRouting = false).AddNewtonsoftJson();
            //.AddNewtonsoftJson();


            //Register server specific for the platform
            services.AddTransient<ITokenManager, JwtManager>();
            services.AddTransient<IAuth, StubAuthenticator>();

            //Register a singleton service managing OPC UA interactions
            services.AddSingleton<IUaClientSingleton, UaClient>();

            //services.AddControllers().AddNewtonsoftJson();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            // Check for invalid HTTP requests before the MVC
            //app.UseRequestValidator();

            app.UseAuthentication();
            app.UseRefreshToken();
            
            app.UseMvc();



        }
    }
}
