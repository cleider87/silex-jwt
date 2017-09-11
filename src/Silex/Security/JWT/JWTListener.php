<?php

namespace Silex\Security;

use HttpEncodingException;
use RESTful\Helpers\Security\TokenEncoderInterface;
use Symfony\Component\HttpFoundation\File\Exception\AccessDeniedException;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\PreAuthenticatedToken;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Silex\Security\JWTToken;

class JWTListener implements ListenerInterface {

    /**
     * @var TokenStorageInterface
     */
    protected $securityContext;

    /**
     * @var AuthenticationManagerInterface
     */
    protected $authenticationManager;

    /**
     * @var TokenEncoderInterface
     */
    protected $encode;

    /**
     * @var array
     */
    protected $options;
    
    protected $session;

    /**
     * @var string
     */
    protected $providerKey;

    function __construct(TokenStorageInterface $securityContext, AuthenticationManagerInterface $authenticationManager, TokenEncoderInterface $encode, $options, $providerKey,$session) {
        $this->securityContext = $securityContext;
        $this->authenticationManager = $authenticationManager;
        $this->encode = $encode;
        $this->session = $session;
        $this->options = $options;
        $this->providerKey = $providerKey;
    }

    /**
     * This interface must be implemented by firewall listeners.
     *
     * @param GetResponseEvent $event
     */
    public function handle(GetResponseEvent $event) {
        $request = $event->getRequest();
        $requestToken = $this->getToken(
                $request->headers->get($this->options['header_name'], null)
        );
        if (!$request->headers->has('Authorization')) {
            $requestToken=$this->session->get('user');
        }
        if (!empty($requestToken)) {
            try {
                $decoded = $this->encode->decode($requestToken);
                $user = null;
                if (isset($decoded->{$this->options['username_claim']})) {
                    $user = $decoded->{$this->options['username_claim']};
                }

                $token = new JWTToken(
                        $user, $requestToken, $this->providerKey
                );

                $authToken = $this->authenticationManager->authenticate($token);
                $this->securityContext->setToken($authToken);
            } catch (HttpEncodingException $e) {
                
            } catch (\UnexpectedValueException $e) {
                
            }
        }
    }

    /**
     * Convert token with prefix to normal token
     *
     * @param $requestToken
     *
     * @return string
     */
    protected function getToken($requestToken) {
        $prefix = $this->options['token_prefix'];
        if (null === $prefix) {
            return $requestToken;
        }

        if (null === $requestToken) {
            return $requestToken;
        }

        $requestToken = trim(str_replace($prefix, "", $requestToken));

        return $requestToken;
    }

}
