﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.Identity.Web.TokenCacheProviders.Distributed
{
    /// <summary>
    /// Extension class used to add an in-memory token cache serializer to MSAL.
    /// </summary>
    public static class DistributedTokenCacheAdapterExtension
    {
        /// <summary>Adds both the app and per-user in-memory token caches.</summary>
        /// <param name="services">The services collection to add to.</param>
        /// <returns>A <see cref="IServiceCollection"/> to chain.</returns>
        public static IServiceCollection AddDistributedTokenCaches(
            this IServiceCollection services)
        {
            AddDistributedAppTokenCache(services);
            AddDistributedUserTokenCache(services);
            return services;
        }

        /// <summary>Adds both the app and per-user .NET Core distributed based token caches.</summary>
        /// <param name="builder">The Authentication builder to add to.</param>
        /// <returns>A <see cref="AuthenticationBuilder"/> to chain.</returns>
        public static AuthenticationBuilder AddDistributedTokenCaches(
            this AuthenticationBuilder builder)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            builder.Services.AddDistributedTokenCaches();
            return builder;
        }

        /// <summary>Adds the .NET Core distributed cache based app token cache to the service collection.</summary>
        /// <param name="services">The services collection to add to.</param>
        /// <returns>A <see cref="IServiceCollection"/> to chain.</returns>
        public static IServiceCollection AddDistributedAppTokenCache(
            this IServiceCollection services)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            services.AddDistributedMemoryCache();
            services.AddSingleton<IMsalTokenCacheProvider, MsalDistributedTokenCacheAdapter>();
            return services;
        }

        /// <summary>Adds the  .NET Core distributed cache based per user token cache to the service collection.</summary>
        /// <param name="services">The services collection to add to.</param>
        /// <returns>A <see cref="IServiceCollection"/> to chain.</returns>
        public static IServiceCollection AddDistributedUserTokenCache(
            this IServiceCollection services)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            services.AddDistributedMemoryCache();
            services.AddHttpContextAccessor();
            services.AddSingleton<IMsalTokenCacheProvider, MsalDistributedTokenCacheAdapter>();
            return services;
        }
    }
}
