<?php

namespace SocialiteProviders\Apple;

use Laravel\Socialite\Two\ProviderInterface;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User;

class Provider extends AbstractProvider implements ProviderInterface
{
    protected $encodingType = PHP_QUERY_RFC3986;
    protected $scopeSeparator = " ";

    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase(
            'https://appleid.apple.com/auth/authorize',
            $state
        );
    }

    protected function getCodeFields($state = null)
    {
        $fields = [
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUrl,
            'scope' => $this->formatScopes($this->getScopes(), $this->scopeSeparator),
            'response_type' => 'code',
            'response_mode' => 'form_post',
        ];

        if ($this->usesState()) {
            $fields['state'] = $state;
        }

        return array_merge($fields, $this->parameters);
    }

    protected function getTokenUrl()
    {
        return "https://appleid.apple.com/auth/token";
    }

    public function getAccessTokenResponse($code)
    {
        $response = $this->getHttpClient()
            ->post(
                $this->getTokenUrl(),
                [
                    'form_params' => $this->getTokenFields($code),
                ]
            );

        return json_decode($response->getBody(), true);
    }

    protected function getTokenFields($code)
    {
        $fields = parent::getTokenFields($code);
        $fields["grant_type"] = "authorization_code";

        return $fields;
    }

    protected function getUserByToken($token)
    {
        $claims = explode('.', $token)[1];

        return json_decode(base64_decode($claims), true);
    }

    public function user()
    {
        $response = $this->getAccessTokenResponse($this->getCode());

        $user = $this->mapUserToObject($this->getUserByToken(
            Arr::get($response, 'id_token')
        ));

        return $user
            ->setToken(Arr::get($response, 'access_token'))
            ->setRefreshToken(Arr::get($response, 'refresh_token'))
            ->setExpiresIn(Arr::get($response, 'expires_in'));
    }

    protected function mapUserToObject(array $user)
    {
        return (new User)
            ->setRaw($user)
            ->map([
                "id" => $user["sub"],
                "email" => $user["email"] ?? null,
            ]);
    }
}
