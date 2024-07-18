<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Google_Client;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class GoogleLoginController extends Controller
{
    public function login(Request $request) {
        $client  = new Google_Client(['client_id' => env('GOOGLE_CLIENT_ID')]);  // Especifica tu Google Client ID aquí
        $payload = $client->verifyIdToken($request->credential);

        if(!$payload) 
            return response()->json(['status' => 'error', 'message' => 'Token ID inválido'], 401);

        $email = $payload['email'];
        $name = $payload['name'];

        [$user, $domain] = explode('@', $email);

        if ($domain !== env('ALLOWED_EMAIL_DOMAIN')) 
            return response()->json(['status' => 'error', 'message' => 'Dominio inválido'], 500);

        $user = [ 'email' => $email, 'name' => $name ];

        $accessToken  = JWT::encode(payload: $user, key: env('API_GA_JWT_SECRET'), alg: 'HS256');
        $refreshToken = JWT::encode(payload: $user, key: env('API_GA_JWT_SECRET'), alg: 'HS256');
        $csrfToken    = bin2hex(random_bytes(32));
        
        return response()->json([
            'user'          => $user,
            'ga_csrf_token' => $csrfToken,
        ])->withCookie(self::createCookie(name: 'ga_access_token' , value: $accessToken ))
          ->withCookie(self::createCookie(name: 'ga_refresh_token', value: $refreshToken))
          ->withCookie(self::createCookie(name: 'ga_csrf_token'   , value: $csrfToken   ));
    }

    public function logout() {
        return response()->json([
            'status' => 'success'
        ])->withCookie(self::createCookie(name: 'ga_access_token' , value: ''))
          ->withCookie(self::createCookie(name: 'ga_refresh_token', value: ''))
          ->withCookie(self::createCookie(name: 'ga_csrf_token'   , value: ''));
    }

    public function refresh_token(Request $request)
    {
        $refreshToken = $request->cookie('ga_refresh_token');
        $accessToken  = $request->cookie('ga_access_token');

        if(!$refreshToken || !$accessToken)
            return response()->json(['status' => 'error', 'message' => 'Token inválido'], 401);

        $payload = JWT::decode($refreshToken, new Key(env('API_GA_JWT_SECRET'), 'HS256'));

        $user = [ 'email' => $payload->email, 'name' => $payload->name ];

        $accessToken  = JWT::encode(payload: $user, key: env('API_GA_JWT_SECRET'), alg: 'HS256');
        $refreshToken = JWT::encode(payload: $user, key: env('API_GA_JWT_SECRET'), alg: 'HS256');
        $csrfToken    = bin2hex(random_bytes(32));

        return response()->json([
            'user'          => $user,
            'ga_csrf_token' => $csrfToken,
        ])->withCookie(self::createCookie(name: 'ga_access_token' , value: $accessToken ))
          ->withCookie(self::createCookie(name: 'ga_refresh_token', value: $refreshToken))
          ->withCookie(self::createCookie(name: 'ga_csrf_token'   , value: $csrfToken   ));
    }
    
    public function createCookie($name, $value){
        return cookie(
            name     : $name, 
            value    : $value, 
            minutes  : 60, 
            path     : null, 
            domain   : null, 
            secure   : true, 
            httpOnly : true, 
            sameSite : 'None'
        );
    }

}
