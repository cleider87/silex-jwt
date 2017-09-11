<?php

/**
 * FORK de https://github.com/cnam/security-jwt-service-provider
 */

namespace RESTful\Helpers\SecuritySilex\Security {

    use Pimple\Container;
    use Pimple\ServiceProviderInterface;
    use Silex\Security\JWTEncoder;
    use Silex\Security\JWTProvider;
    use Silex\Security\JWTListener;
    use Silex\Security\JwtAuthenticationEntryPoint;
    use Symfony\Component\Security\Http\Logout\DefaultLogoutSuccessHandler;
    
    class SecurityJWTServiceProvider implements ServiceProviderInterface {

        public function register(Container $app) {
            $app['security.jwt'] = array_replace_recursive([
                'secret_key' => 'default_secret_key',
                'life_time' => 86400,
                'algorithm' => ['HS256'],
                'options' => [
                    'username_claim' => 'name',
                    'header_name' => 'SECURITY_TOKEN_HEADER',
                    'token_prefix' => null,
                ]
                    ], $app['security.jwt']);

            $app['security.jwt.encoder'] = function() use ($app) {
                return new JWTEncoder($app['security.jwt']['secret_key'], $app['security.jwt']['life_time'], $app['security.jwt']['algorithm']);
            };

            $app['security.authentication.success_handler.secured'] = function () use ($app) {
                return new Authentication\DefaultAuthenticationSuccessHandler($app['security.http_utils'], []);
            };

            $app['security.authentication.failure_handler.secured'] = function () use ($app) {
                return new Authentication\DefaultAuthenticationFailureHandler($app['request'], $app['security.http_utils'], []);
            };

            $app['security.authentication.logout_handler.secured'] = function () use ($app) {
                return new DefaultLogoutSuccessHandler($app['security.http_utils'], []);
            };

            /**
             * Class for usage custom listeners
             */
            $app['security.jwt.authentication_listener'] = function() use ($app) {
                return new JWTListener($app['security.token_storage'], $app['security.authentication_manager'], $app['security.jwt.encoder'], $app['security.jwt']['options'], 'jwt',$app['session']);
            };

            /**
             * Class for usage custom user provider
             */
            $app['security.jwt.authentication_provider'] = function() use ($app) {
                return new JWTProvider($app['users'], $app['security.user_checker'], "jwt");
            };

            $app['security.entry_point.jwt'] = function() use ($app) {
                return new JwtAuthenticationEntryPoint();
            };

            $app['security.authentication_listener.factory.jwt'] = $app->protect(function ($name, $options) use ($app) {
                $app['security.authentication_listener.' . $name . '.jwt'] = function() use ($app) {
                    return $app['security.jwt.authentication_listener'];
                };
                $app['security.authentication_provider.' . $name . '.jwt'] = function() use ($app) {
                    return $app['security.jwt.authentication_provider'];
                };
                return array(
                    'security.authentication_provider.' . $name . '.jwt',
                    'security.authentication_listener.' . $name . '.jwt',
                    'security.entry_point.jwt',
                    'pre_auth'
                );
            });
        }

    }

}
